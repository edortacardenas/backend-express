import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github';

import  User  from '../databases/shemas/user.js'; //Import User model
import bcrypt from 'bcryptjs';
import { generateOTP, transporter } from '../utils/mail.js';

passport.serializeUser((user, done) => {
    console.log("Dentro de serialize user")
    done(null, user.id);
})

passport.deserializeUser(async (id, done) => {
    console.log("Dentro de Deserialize user")
    try {
        const findUser = await User.findByPk(id)
        if(!findUser) throw new Error(`User not found whith id ${id}`)
        done(null, findUser);
    } catch (error) {
        done(error, null);
        
    }
})

passport.use(
    new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
  },
  async (accessToken, refreshToken, profile, done) => {
    console.log("Dentro de google strategy")
    let findUserEmail;
    let findUserGoogle;
    try {
        //Check if the user already exists in our database
        const email = profile.emails?.[0]?.value || null;
        findUserGoogle = await User.findOne({ where: { googleId: profile.id } });
        if (email) {
            findUserEmail =await User.findOne({ where: { email } }) 
        }
    } catch (error) {
        console.log(error)
        return done(error, null)
    }
    
    try {
        //Check if the user with githubId already exists in our database
        // Si el usuario ya existe por githubId, retorna el usuario
        if (findUserGoogle) {
            return done(null, findUserGoogle);
        }

        //If user exists by email but not by googleId
        if (findUserEmail && (!findUserGoogle || !findUserGoogle.googleId)) {
            //Update user with googleId
            findUserEmail.googleId = profile.id;
            await findUserEmail.save(); // Guarda los cambios en la base de datos

            return done(null, findUserGoogle)
            
        }

        //If user does not exist by googleId or email, create a new user
        if (!findUserGoogle && !findUserEmail) {
            const newSavedUser = await User.create({ 
                name: profile.displayName || "User Google", 
                googleId: profile.id,
                email: profile.emails?.[0]?.value || null,
                isVerified: false, 
        });
            return done(null, newSavedUser);
        }
        
    } catch (error) {
        console.log(error)
        return done(error, null)
    }
    }
));

passport.use(
    new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL
  },
  async (accessToken, refreshToken, profile, done) => {
    console.log("Dentro de github strategy")
    let findUserEmail;
    let findUserGithub;
    try {
        //Check if the user already exists in our database
        const email = profile.emails?.[0]?.value || null;
        findUserGithub =await User.findOne({  where:  {githubId: profile.id } });
        if (email) {
            findUserEmail =await User.findOne({ where: { email } }) 
        }
        
    } catch (error) {
        console.log(error)
        return done(error, null)
    }

    
    try {
        //Check if the user with githubId already exists in our database
        if (findUserGithub) {
            return done(null, findUserGithub);
        }

        //If user exists by email but not by githubId
        if (findUserEmail && (!findUserGithub || !findUserGithub.githubId)) {
            //Update user with githubId
            findUserEmail.githubId = profile.id;
            await findUserEmail.save(); // Guarda los cambios en la base de datos

            return done(null, findUserGithub)
            
        }

        //If user does not exist by googleId or email, create a new user
        if (!findUserGithub && !findUserEmail) {
            const newSavedUser = await User.create({ 
                name: profile.displayName || "User Github", 
                githubId: profile.id,
                email: profile.emails?.[0]?.value || null,
                isVerified: false, 
        });
            return done(null, newSavedUser);
        }
                

    } catch (error) {
        console.log(error)
        return done(error, null)
    }
    }
));

export default passport.use(
    new LocalStrategy( {usernameField: "email"}, async (email, password, done) => {
        console.log("Dentro de local estrategy")
        try {
            
            // Verifica si el usuario existe en la base de datos por correo
            let findUserByEmail = await User.findOne({ where: { email } });

            if (!findUserByEmail) {
                console.log("No Encuentra el usuario")
                return done(null, false, { msg: 'User with local strategy not found' });
                
            }

            if (findUserByEmail && findUserByEmail.password !== null  ) {
                const isMatch = await bcrypt.compare(password, findUserByEmail.password);
                if (!isMatch) {
                    console.log("Credenciales incorrectas")
                    return done(null, false, { msg: "Credenciales incorrectas" });
                }

                // Si la contraseña es correcta e email no verificado retorna mensaje
                if (isMatch && findUserByEmail.isVerified === false) {
                    console.log("Por favor verifica el email")
                    
                    await findUserByEmail.save();
                    return done(null, false, { msg: "Por favor verifica el email " });
                }

                // Si la contraseña es correcta e email verificado retorna el usuario
                if (isMatch && findUserByEmail.isVerified) {
                    console.log("Encontro el usuario por el email, el usuario esta verificado y contraseña coinciden")
                    return done(null, findUserByEmail);
                }
           }
           
            if (findUserByEmail && findUserByEmail.password === null) {
                console.log("Usuario registrado por oauth sin contraseña")
                return done(null, false, { msg: 'Usuario registrado por oauth sin contraseña' });
            }           
            
    
        } catch (error) {
            console.log(error)
            return done(error, null)
        }
        }
    )  
)

