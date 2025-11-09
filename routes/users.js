import { Router } from "express";
import { query, validationResult, body, matchedData, checkSchema } from "express-validator"//Import express-validator
import { createUserValidationShema, 
    queryValidationUserShema, 
    loginValidationUserShema, 
    PutUserValidationShema, // Asumo que este existe, si no, ignóralo o créalo
    changePasswordValidationSchema, // Importar el nuevo esquema
    PatchUserValidationShema
} from '../utils/validationShemas.js';

import  User  from "../databases/shemas/user.js"; //Import the user shema
import passport from 'passport';
import bcrypt from "bcryptjs"
import { Op } from 'sequelize';
import {generateOTP, transporter} from "../utils/mail.js" //Import the transporter and generateOTP function
import crypto from 'node:crypto'; // Import the built-in crypto module

const router = Router()

//Middleware to check if the user is authenticated
//This middleware will check if the user is authenticated and if not it will return a 401 error

const authValid = (req, res, next) => {
    console.log("Entro al middleware authValid")
    if (req.isAuthenticated()) { // req.isAuthenticated()método proporcionado por passport verifica si el usuario está autenticado.
      // Si el usuario está autenticado, continúa con la siguiente función
      console.log("Esta autenticado")
      return next();
    } else {
      // Si no está autenticado, manda un mensaje 
      console.log("No esta autenticado")
      return res.status(401).send({ msg: "Unauthorized User" }); 
    }
};

//Middleware to check if the user is an admin
const isAdmin = (req, res, next) => {
    console.log("Entro al middleware isAdmin")
    if (req.user && req.user.role === 'admin') {
        console.log("Es admin")
        return next();
    }
    return res.status(403).send({ msg: "Forbidden: Admin access required" });
}

/////////  Autentication with passport into database using local-stategies username and password   ///////////////
// api/register
// api/login
// api/login/status
// api/logout


//Endpoint to create a new user into the database
router.post('/register', checkSchema(createUserValidationShema), async (req, res) => {
    const result = validationResult(req);
    if (!result.isEmpty()) {
        return res.status(400).send({ msg: result.array() });
    }

    console.log("Dentro de la ruta register")
    const data = matchedData(req);
    const { email, password } = data;

    
    try {
        // Verificar si el usuario ya existe
        const existingUser = await User.findOne({ where: { email } });

        if (existingUser) {
            if (existingUser.password) {
            // Si el usuario ya tiene una contraseña, no permitir el registro
            return res.status(400).send({ msg: "Email already in use with a password" });
            }else{
                const hashedPassword = await bcrypt.hash(password, 10);
                existingUser.password =hashedPassword,
                existingUser.isVerified = false,
                await existingUser.save();
                return res.status(201).send({msg:"User created successfully by local strategy"})
            }
        }

        
        if (!existingUser) {
           // Crear un nuevo usuario si no existe
            const hashedPassword = await bcrypt.hash(password, 10);
            const newUser = await User.create({
                ...data,
                password: hashedPassword,
                isVerified: false,
            });
            return res.status(201).send({ msg:"User created successfully by local strategy please verify your email"}); 
        }
        
    } catch (err) {
        console.error(err);
        return res.status(500).send({ msg: "Error saving user" });
    }
});

//Endpoint to send an OTP
router.post('/send-otp', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).send({ msg: "Email is required." });
    }

    try {
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(404).send({ msg: "User not found with this email." });
        }

        if (!user.password) {
            return res.status(401).send({ msg: "User dont have a password user register by oauth" })
        }

        if (user.isVerified) {
            return res.status(400).send({ msg: "User is already verified. You can log in." });
        }

        const otp = generateOTP();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // OTP expires in 10 minutes

        user.otp = otp;
        user.otpExpiry = otpExpiry;
        await user.save(); // Save OTP to user first

        // Send email (await will wait for the promise to resolve/reject if no callback is passed)
        const mailInfo = await transporter.sendMail({
            from: process.env.USER_MAIL,
            to: email,
            subject: 'Your One-Time Password (OTP)',
            text: `Your OTP for account verification is: ${otp}. It will expire in 10 minutes.`,
        });
        console.log('OTP email sent successfully:', mailInfo.response);

        return res.status(200).send({ msg: "OTP has been sent to your email. Please check your inbox." });

    } catch (err) {
        console.error("Error in /send-otp endpoint:", err);
        // A generic error message is safer for the client.
        return res.status(500).send({ msg: "An error occurred while trying to send the OTP. Please try again later." });
    }
});


//Endpoint to verify the OTP
router.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;

    try {
        // Verificar si el usuario existe
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(404).send({ msg: "User not found" });
        }

        if (user.isVerified) {
            return res.status(400).send({ msg: "User already verified" });
            
        }

        // Verificar si el OTP es correcto y no ha expirado
        if (user.otp !== otp || user.otpExpiry < new Date()) {
            return res.status(400).send({ msg: "Invalid or expired OTP" });
            
        } else {
            user.isVerified = true;
            user.otp = null; // Limpiar el OTP después de la verificación
            await user.save();
            return res.status(200).send({ msg: "Email verified successfully. You can now log in" });
        }
    } catch (err) {
        console.error(err);
        return res.status(500).send({ msg: "Error verifying OTP" });
    }

})

//Endpoint to resend the OTP
router.post('/resend-otp', async (req, res) => {
    const { email } = req.body;

    try {
        // Verificar si el usuario existe
        const user = await User.findOne({ where: { email } });

        if (!user) {
            return res.status(404).send({ msg: "User not found" });
        }

        if (user.isVerified) {
            return res.status(400).send({ msg: "User already verified" });
            
        }

        const otp = generateOTP(); // Generar un nuevo OTP
        user.otp = otp;
        user.otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // Expira en 10 minutos
        await user.save();

        await transporter.sendMail(
            {
            from: process.env.USER_MAIL,
            to: email,
            subject: 'Resend OTP Verification',
            text: `Your new OTP is: ${otp}`,
            },
            (error, info) => {
            if (error) {
                console.error('Error al enviar el correo:', error);
            } else {
                console.log('Correo enviado:', info.response);
            }
        });

        return res.status(200).send({ msg:"New OTP sent successfully"}); 
    } catch (err) {
        console.error(err);
        return res.status(500).send({ msg: "Error sending OTP" });
    }
})

// Endpoint para solicitar el restablecimiento de contraseña
router.post("/reset-password", async (req, res) => {
    const { email } = req.body;
    console.log("Llego a reset-password endpoint")
  
    try {
      // Verificar si el usuario existe
      const user = await User.findOne({ where: { email } });
      if (!user) {
        return res.status(404).send({ msg: "User not found by the email provided" });
      }
      if (!user.password) {
        return res.status(404).send({ msg: "User does't have a password try to registry by local estrategy" });
      }
  
      // Generar un token único para el restablecimiento de contraseña
      const resetToken = crypto.randomBytes(32).toString("hex");
      const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hora de validez
  
      // Guardar el token y su expiración en la base de datos
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpiry = resetTokenExpiry;
      await user.save();
  
      // Crear el enlace de restablecimiento de contraseña
      // This link should point to your frontend application's reset password page
      // Assuming your frontend is on http://localhost:5173 and has a route like /reset-password/:token
      const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
  
      // Configurar el correo electrónico
      const mailOptions = {
        from: process.env.USER_MAIL,
        to: email,
        subject: "Password Reset Request",
        html: `
          <p>Hello,</p>
          <p>You requested to reset your password. Click the link below to reset it:</p>
          <a href="${resetLink}" target="_blank">${resetLink}</a>
          <p>If you did not request this, please ignore this email.</p>
        `,
      };
  
      // Enviar el correo electrónico
      await transporter.sendMail(mailOptions);
  
      res.status(200).send({ msg: "Password reset email sent successfully" });
    } catch (error) {
      console.error("Error in reset-password endpoint:", error);
      res.status(500).send({ msg: "Internal server error" });
    }
  });
  
  // Endpoint para actualizar la contraseña
  router.post("/reset-password/:token", async (req, res) => {
    console.log("Llego a reset password/:token endpoint")
    
    const { token } = req.params;
    const { newPassword } = req.body; // Make sure 'newPassword' is sent from the frontend
    console.log(token, newPassword)
    try {
      // Buscar al usuario por el token y verificar si el token no ha expirado
      const user = await User.findOne({
        where: {
          resetPasswordToken: token,
          resetPasswordExpiry: { [Op.gt]: new Date() }, // Verifica que el token no haya expirado
        },
      });
  
      if (!user) {
        return res.status(400).send({ msg: "Invalid or expired token" });
      }

      // Validate that newPassword is provided and is a string
      if (!newPassword || typeof newPassword !== 'string' || newPassword.trim() === '') {
        return res.status(400).send({ msg: "New password is required and must be a non-empty string." });
      }
  
      // Actualizar la contraseña del usuario
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      user.resetPasswordToken = null; // Limpiar el token
      user.resetPasswordExpiry = null; // Limpiar la expiración
      await user.save();
  
      res.status(200).send({ msg: "Password reset successfully" });
    } catch (error) {
      console.error("Error in reset-password token endpoint:", error);
      res.status(500).send({ msg: "Internal server error" });
    }
  });





//Endpoint to authenticate a user with passport and local strategy and express-session
router.post(
    "/login",
    checkSchema(loginValidationUserShema), // Middleware de validación
    (req, res, next) => {
      // Captura los errores de validación
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).send({ msg: "Validation errors", errors: errors.array() });
      }
      next(); // Si no hay errores, pasa al siguiente middleware
    }, (req, res, next) => { // Added 'next' for consistency, though passport.authenticate usually handles response
        passport.authenticate("local", (err, user, info) => {
            console.log("Dentro de la ruta login")
            if (err) {
                return res.status(500).send({ msg: info?.message || "Error en la autenticación" });
            }
            
            if (!user) {
                return res.status(404).send({ msg: info }); // Usuario no encontrado
            }

            req.login(user, (err) => {
                if (err) {
                    return res.status(500).send({ msg: "Error al iniciar sesión de usuario" });
                }
                // Successful authentication, session established.
                // Now, determine if MFA (via initial OTP or email verification for MFA) is needed.
                // Your frontend's onSubmitHelper expects a message containing "verifica"
                // or a more structured response.
                if (!user.isVerified) { // For initial email OTP verification
                    return res.status(400).send({ msg: "Usuario no verificado, por favor verifica tu correo con el OTP." });
                }
                // Add your logic here if MFA is enabled for already verified users
                // For example: if (user.mfaEnabled) { return res.status(400).send({ msg: "MFA es requerido, por favor verifica."})}

                return res.status(200).send({ msg: "Usuario ha iniciado sesión correctamente" });
            });
        })(req, res, next); // Pass req, res, next to the authenticator
    });

//Endpoint to chek if the user is authenticated
router.get("/login/status", authValid, (req, res) => {
    if (req.session && req.session.passport && req.session.passport.user) {
        // El usuario está autenticado
        return res.send({ isAuthenticated: true, user: req.user });
    }
    return res.status(401).send({ isAuthenticated: false, msg: "User not authenticated" });
})

//Endpoint to logout the user
router.post("/logout", authValid, (req, res) => {
    console.log("User before logout:", req.user);
    if(!req.user) return res.status(401).send({msg: "User not authenticated"})

    req.logout((err) => {
        if (err) {
            console.error('Error during logout:', err);
            return res.status(500).send('Error during logout');
        }
        req.session.destroy((err) => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.status(500).send('Error destroying session');
            }
            console.log("Session destroyed");
            res.clearCookie('connect.sid'); // Limpia la cookie de sesión
            res.status(200).send({ msg: "Logout successful" }); // Responde con éxito
        });
    });
})

////  Rutas para usar nodemail en local-strategy  /////
// New endpoint: Request email verification (for initial verification or MFA)
router.post("/auth/request-email-verification", async (req, res) => { // Removed authValid
    console.log("Entro a request-email-verification");
    const { email } = req.body; // Expect email in the request body

    if (!email) {
        return res.status(400).send({ msg: "Email es requerido." });
    }
    
    try {
        // Find user by email provided in the request body
        const user = await User.findOne({ where: { email } }); 

        if (!user) {
            return res.status(404).send({ msg: "Usuario no encontrado." });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expiryDate = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos de expiración

        user.emailVerificationToken = token;
        user.emailVerificationExpiry = expiryDate;
        await user.save();

        const verificationLink = `${process.env.FRONTEND_URL }/verify-email?token=${token}`;

        // Asumiendo que tienes una función sendVerificationEmail en utils/mail.js o similar
        // que toma (toEmail, subject, htmlContentOrText)
        // Necesitarás adaptar esto a tu implementación exacta de envío de correo.
        await transporter.sendMail({
            from: process.env.USER_MAIL, // o process.env.EMAIL_FROM
            to: user.email,
            subject: 'Verifica tu Correo para Iniciar Sesión (MFA)',
            html: `<p>Hola,</p><p>Has solicitado iniciar sesión y se requiere verificación por correo electrónico.</p><p>Por favor, haz clic en el siguiente enlace para verificar tu identidad:</p><p><a href="${verificationLink}">Verificar Correo Electrónico</a></p><p>Este enlace expirará en 15 minutos.</p><p>Si no solicitaste esto, por favor ignora este correo.</p>`,
        });

        res.status(200).send({ msg: "Correo de verificación enviado. Revisa tu bandeja de entrada." });

    } catch (error) {
        console.error("Error al solicitar verificación por correo:", error);
        try {
            // Attempt to find user by email again to clear token if it was set
            const userToClearOnError = await User.findOne({ where: { email } });
            if (userToClearOnError && userToClearOnError.emailVerificationToken) {
                 userToClearOnError.emailVerificationToken = null;
                 userToClearOnError.emailVerificationExpiry = null;
                 await userToClearOnError.save();
             }
        } catch (clearError) {
            console.error("Error al limpiar token después de fallo de envío de correo:", clearError);
        }
        res.status(500).send({ msg: "Error al enviar el correo de verificación." });
    }
});

// New endpoint: Complete email verification (MFA step)
router.post("/auth/complete-email-verification", async (req, res) => { // Removed authValid
    console.log("Entro a complete-email-verification");
    const { token } = req.body;
    // User is identified by the token, not by an active session's req.user.id

    if (!token) {
        return res.status(400).send({ msg: "Token de verificación no proporcionado." });
    }

    try {
        const user = await User.findOne({
            where: {
                // id: userId, // Not used if authValid is removed
                emailVerificationToken: token,
                emailVerificationExpiry: { [Op.gt]: new Date() } // Check if token is not expired
            }
        });

        if (!user) {
            // If no user found with this token, or if it's expired
            return res.status(400).send({ msg: "Token de verificación inválido o expirado." });
        }

        // Token is valid
        user.emailVerificationToken = null; // Clear the token
        user.emailVerificationExpiry = null; // Clear the expiry
        
        // If this is for initial verification, set isVerified to true
        if (!user.isVerified) {
            user.isVerified = true;
        }

        // Optionally, you might have a flag in the session or user model to indicate MFA completion for this session
        // For example: req.session.mfaVerified = true; or user.mfaVerifiedAt = new Date();
        await user.save();

        res.status(200).send({ msg: "Verificación por correo completada exitosamente. Puedes continuar." });
    } catch (error) {
        console.error("Error al completar la verificación por correo:", error);
        res.status(500).send({ msg: "Error interno del servidor al verificar el token." });
    }
});


// Ruta protegida: Obtener información del usuario autenticado
router.get("/profile", authValid, async (req, res) => {
    try {
      const user = await User.findByPk(req.user.id); // Obtén el usuario autenticado
      if (!user) {
        return res.status(404).send({ msg: "Usuario no encontrado" });
      }
      res.status(200).send(user);
    } catch (error) {
      console.error("Error al obtener el perfil del usuario:", error);
      res.status(500).send({ msg: "Error interno del servidor" });
    }
});

// Ruta protegida: Actualizar información del usuario autenticado
router.patch("/profile", authValid, checkSchema(PatchUserValidationShema), async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id); // Obtén el usuario autenticado
        if (!user) {
          return res.status(404).send({ msg: "Usuario no encontrado" });
        }
        const result = validationResult(req) 
        //Check if the are no errors if there are send the errors
        if(!result.isEmpty()){
            return res.status(400).send({ msg: result.array() });
        }
        //Get the data from the request using matchedData to be sure that the data is valid
        const data = matchedData(req)
        const updates = data; // Obtén los datos del cuerpo de la solicitud

        // Prevent users from updating their own role via this endpoint
        if (updates.hasOwnProperty('role')) {
            delete updates.role;
            // Optionally, log or inform that role update is not allowed here
        }
        
        // Verifica si el cuerpo de la solicitud contiene datos
        if (!updates || Object.keys(updates).length === 0) {
            return res.status(400).send({ msg: "No fields provided for update" });
        }

        //Tomo el id del usuario autenticado
        //user.dataValues objeto que contiene los valores del usuario autenticado
        const id = user.dataValues.id

        // Actualiza los campos del usuario
        await User.update(
            updates, // Campos a actualizar
            { where: { id  } } // Condición para encontrar el registro
        );
        
        res.status(200).send({msg: "User actualizado correctamente"});
    } catch (error) {
        console.error("Error al obtener el perfil del usuario:", error);
        res.status(500).send({ msg: "Error interno del servidor" });
    }
})

// Ruta protegida: Eliminar usuario autenticado
router.delete("/profile", authValid, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id); // Obtén el usuario autenticado
        if (!user) {
          return res.status(404).send({ msg: "Usuario no encontrado" });
        }
        const id = user.dataValues.id
        // Elimina el usuario de la base de datos
        await User.destroy(
            { where: { id } } // Condición para encontrar el registro
        );

        // Envía mensaje de usuario eliminado como respuesta
        req.logout((err) => {
            if (err) {
                console.error('Error during logout:', err);
                return res.status(500).send('Error during logout');
            }
            req.session.destroy((err) => {
                if (err) {
                    console.error('Error destroying session:', err);
                    return res.status(500).send('Error destroying session');
                }
                res.clearCookie('connect.sid'); // Limpia la cookie de sesión
                res.status(200).send({ msg: "Logout successful" }); // Responde con éxito
            });
        });
    
    } catch (error) {
        console.error("Error al eliminar el usuario:", error);
        return res.status(500).send({ msg: "Internal server error" });
    }    
})

// Ruta protegida: Cambiar contraseña del usuario autenticado
router.patch("/profile/change-password", authValid, checkSchema(changePasswordValidationSchema), async (req, res) => {
    const result = validationResult(req);
    if (!result.isEmpty()) {
        return res.status(400).send({ msg: "Errores de validación", errors: result.array() });
    }

    const { oldPassword, newPassword } = matchedData(req);
    const userId = req.user.id;

    try {
        const user = await User.findByPk(userId);

        if (!user) {
            // Esto no debería ocurrir si authValid funciona correctamente
            return res.status(404).send({ msg: "Usuario no encontrado." });
        }

        // 1. Verificar si el usuario tiene una contraseña (registro local)
        if (!user.password) {
            return res.status(400).send({ msg: "No puedes cambiar la contraseña porque te registraste usando un proveedor externo (ej. Google, GitHub)." });
        }

        // 2. Validar la contraseña anterior
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            return res.status(400).send({ msg: "La contraseña anterior es incorrecta." });
        }

        // 3. Validar que la nueva contraseña no sea igual a la anterior (opcional pero recomendado)
        if (oldPassword === newPassword) {
            return res.status(400).send({ msg: "La nueva contraseña no puede ser igual a la anterior." });
        }

        // 4. Hashear y actualizar la nueva contraseña
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedNewPassword;

        // Opcional: Invalidar tokens de reseteo si existieran, aunque no es estrictamente necesario aquí
        // user.resetPasswordToken = null;
        // user.resetPasswordExpiry = null;

        await user.save();

        res.status(200).send({ msg: "Contraseña actualizada correctamente." });

    } catch (error) {
        console.error("Error al cambiar la contraseña:", error);
        res.status(500).send({ msg: "Error interno del servidor al intentar cambiar la contraseña." });
    }
});



///////  Autentication with passport into database using github  ///////////////

///////////   Endpoint to authenticate a user with passport and github strategy  /////

router.get('/auth/github', passport.authenticate('github'));
  
router.get("/auth/callback/github", 
passport.authenticate('github', { 
    failureRedirect: `${process.env.FRONTEND_URL}/login`, //Redirect to the login page if the authentication fails
    successRedirect: `${process.env.FRONTEND_URL}/dashboard`  }), //Redirect to the frontend
function(req, res) {
    // Successful authentication, redirect home.
    console.log(req.session)
    console.log(req.user)
    res.status(200).send("User loggined in with github");
});

///////  Autentication with passport into database using google ///////////////

////////////Endpoint to authenticate a user with passport and google strategy

router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get("/auth/callback/google", 
    passport.authenticate('google', {
        failureRedirect: `${process.env.FRONTEND_URL}/login`, //Redirect to the login page if the authentication fails
        successRedirect: `${process.env.FRONTEND_URL}/dashboard`  }),
    (req, res) => {
        res.status(200).send("User loggined in with google");
});



///////  POST request to create a new user into the database  ////////////////


router.post('/users', authValid, isAdmin, checkSchema(createUserValidationShema), async (req, res)=> {
    const result = validationResult(req) 
    //Check if the are no errors if there are send the errors
    if(!result.isEmpty()){
        return res.status(400).send({ msg: result.array() });
    }
    //Get the data from the request using matchedData to be sure that the data is valid
    const data = matchedData(req);

    const { name, email, password, role } = data;

    const userToCreate = {
        name,
        email,
    };

    if (password) {
        userToCreate.password = await bcrypt.hash(password, 10);
    }

    if (role) { // If role is provided and validated, use it
        userToCreate.role = role;
    }
    // If role is not provided, the Sequelize model's defaultValue ('user') will be used.
    // isVerified defaults to false as per the model.
    // OTP fields will be null/empty by default.

    //Save user to the database
    try {
        // Check if user already exists
        const existingUser = await User.findOne({ where: { email: email } });
        if (existingUser) {
            return res.status(400).send({ msg: "User with this email already exists." });
        }

        const savedUser = await User.create(userToCreate); 

        // Exclude sensitive information from the response
        const userResponse = { ...savedUser.get({ plain: true }) };
        delete userResponse.password;
        delete userResponse.otp;
        delete userResponse.otpExpiry;
        delete userResponse.resetPasswordToken;
        delete userResponse.resetPasswordExpiry;

        return res.status(201).send(userResponse);
        
    } catch (err) {
        console.error("Error saving user by admin:", err);
        if (err.name === 'SequelizeUniqueConstraintError') { // More specific error for unique fields
            return res.status(400).send({ msg: "Email or other unique field already in use." });
        }
        return res.status(500).send({ msg: "Error saving user"});
    }
})


//Put request to update a user in the database 
router.put('/users/:id', authValid, checkSchema(PutUserValidationShema), async (req, res) => {
    const { id } = req.params; // Obtén el ID del usuario desde los parámetros

    // Verifica si el ID tiene un formato válido 
    if (isNaN(id)) {
        return res.status(400).send({ msg: "Invalid ID format" });
    }

    const result = validationResult(req) 
    //Check if the are no errors if there are send the errors
    if(!result.isEmpty()){
        return res.status(400).send({ msg: result.array() });
    }
    //Get the data from the request using matchedData to be sure that the data is valid
    const data = matchedData(req)
  
    const { username, displayName } = data; // Obtén los datos del cuerpo de la solicitud

    let updatedUser ;
    try {
        // Busca y actualiza el usuario en la base de datos
        updatedUser= await User.findByPk( id);

        // Si no se encuentra el usuario, devuelve un error
        if (!updatedUser) {
            return res.status(404).send({ msg: "User not found" });
        }

        // Actualiza los campos del usuario
        await User.update(
            { username, displayName }, // Campos a actualizar
            { where: { id } } // Condición para encontrar el registro
        );
       
        // Envía el usuario actualizado como respuesta
        updatedUser= await User.findByPk( id);
        res.status(200).send(updatedUser);
    } catch (error) {
        console.error("Error al actualizar el usuario:", error);
        res.status(500).send({ msg: "Internal server error" });
    }
});


//Patch request to update partially an user in the database
router.patch('/users/:id', authValid, isAdmin, checkSchema(PatchUserValidationShema), async (req, res) => {

    const { id } = req.params; // Obtén el ID del usuario desde los parámetros

    // Verifica si el ID tiene un formato válido 
    if (isNaN(id)) {
        return res.status(400).send({ msg: "Invalid ID format" });
    }

    const result = validationResult(req) 
    //Check if the are no errors if there are send the errors
    if(!result.isEmpty()){
        return res.status(400).send({ msg: result.array() });
    }
    //Get the data from the request using matchedData to be sure that the data is valid
    const data = matchedData(req)
    const updates = data; // updates will contain 'role' if sent and validated by PatchUserValidationShema

    // The 'role' field will be part of 'updates' if it was sent in the request
    // and validated by PatchUserValidationShema.
    
    // Verifica si el cuerpo de la solicitud contiene datos
    if (!updates || Object.keys(updates).length === 0) {
        return res.status(400).send({ msg: "No fields provided for update" });
    }

    let updatedUser ;
    try {
        // Busca y actualiza el usuario en la base de datos
        updatedUser= await User.findByPk( id);

        // Si no se encuentra el usuario, devuelve un error
        if (!updatedUser) {
            return res.status(404).send({ msg: "User not found" });
        }

        // Actualiza los campos del usuario
        await User.update(
            updates, // Campos a actualizar
            { where: { id } } // Condición para encontrar el registro
        );
       
        // Envía el usuario actualizado como respuesta
        updatedUser= await User.findByPk( id);
        res.status(200).send(updatedUser);
    } catch (error) {
        console.error("Error al actualizar el usuario:", error);
        res.status(500).send({ msg: "Internal server error" });
    }
       
})

//Delete request to delete an user in the database
router.delete('/users/:id', authValid, async (req, res) => {
    const { id } = req.params; // Obtén el ID del usuario desde los parámetros

    // Verifica si el ID tiene un formato válido 
    if (isNaN(id)) {
        return res.status(400).send({ msg: "Invalid ID format" });
    }
     //Delete the user in the database
    try {
        const deletedUser = await User.findByPk(id);

        // Si no se encuentra el usuario, devuelve un error
        if (!deletedUser) {
            return res.status(404).send({ msg: "User not found" });
        }

        // Elimina el usuario de la base de datos
        await User.destroy(
            { where: { id } } // Condición para encontrar el registro
        );

        // Envía el usuario eliminado como respuesta
        res.status(200).send(deletedUser);
    
    } catch (error) {
        console.error("Error al eliminar el usuario:", error);
        res.status(500).send({ msg: "Internal server error" });
    }    
})

//Get request to get all users in the database
//Filtered by username or displayName

router.get('/users', authValid, checkSchema(queryValidationUserShema), async (req, res) => {
    //Calling validation result and pass the request object
    const result = validationResult(req) 

    //Using matchedData to get the data from the request and validate it
    //matchedData will return an object with the data that was validated
    const data = matchedData(req)
    //Destructure the query parameters from the data already validated
    const { filter, value } = data;
    
    //Check if the query parameters are present
    if (!filter && !value) {
        try {
            const users = await User.findAll();// Obtiene todos los usuarios de la base de datos
            return users.length > 0 ? res.status(200).send(users) : res.status(200).send({msg: "No existen usuarios"}); // Envía la lista de usuarios como respuesta
        } catch (error) {
            console.error("Error al obtener los usuarios:", error);
            return res.status(500).send({ msg: "Internal server error" });
        }
    }
    if (!result.isEmpty()) {
        return res.status(400).send({ msg: result.array() });
    }
    //Check if the query parameters are valid
    if (!filter || !value) {
        return res.status(401).send({ msg: "Missing or invalid query parameters" });
    }
    if (filter && value) {
        //Check if the filter is valid
        if (filter !== "name" ) {
            return res.status(400).send({ msg: "Invalid filter" });
        }
        try {
            const filteredUsers = await User.findAll({
                where: {
                    [filter]: {
                        [Op.iLike]: `%${value}%`,
                    },
                },
            });
            //Check if the filtered users are present
            if (filteredUsers.length === 0) {
                return res.status(404).send({ msg: "No users found" });
            }
            return res.send(filteredUsers);
        } catch (error) {
            console.error("Error in query:", error);
            return res.status(500).send({ msg: "Internal server error" });
        }
        
        
    }    
    
});



router.get("/users/:id", authValid, async (req, res) =>{
    const { id } = req.params; // Obtén el ID del usuario desde los parámetros
    
    // Verifica si el ID tiene un formato válido 
    if (isNaN(id)) {
        return res.status(400).send({ msg: "Invalid ID format" });
    }

     //Delete the user in the database
    try {
        const findUser = await User.findByPk(id); // Busca un usuario por el id

        // Si no se encuentra el usuario, devuelve un error
        if (!findUser) {
            return res.status(404).send({ msg: "User not found" });
        }

        // Envía el usuario eliminado como respuesta
        return res.status(200).send(findUser);
    
    } catch (error) {
        console.error("No se encontro el usuario con ese id", error);
        return res.status(500).send({ msg: "Internal server error" });
    }    
})

// Endpoint to check if the authenticated user is an admin
router.get("/admin/status", authValid, async (req, res) => {
    console.log("Entro a la ruta /admin/status")
    try {
      // req.user should be populated by Passport and contain the authenticated user's data
      // including the isAdmin field from your User model.
      if (!req.user) {
        // This case should ideally be caught by authValid, but as a safeguard:
        console.error("User not authenticated");
        return res.status(401).send({ msg: "User not authenticated" });
      }
      
      return res.status(200).send({ isAdmin: req.user.role === "admin" });
    } catch (error) {
      console.error("Error checking admin status:", error);
      return res.status(500).send({ msg: "Internal server error" });
    }
});


export default router;