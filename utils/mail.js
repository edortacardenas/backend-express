
import nodemailer from 'nodemailer';

//Email transporter setup
export const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.USER_MAIL,
        pass: process.env.USER_MAIL_PASSWORD,
    },
})


//Generate OTP
export const generateOTP = () => {
    // Generate a 6-digit OTP
    return Math.floor(100000 + Math.random() * 900000).toString();
};

/*export const sendVerificationEmail = async (toEmail, verificationLink) => {
    const mailOptions = {
        from: process.env.USER_MAIL|| '"Your App Name" <no-reply@example.com>', // Sender address
        to: toEmail, // List of recipients
        subject: 'Verifica tu Correo Electrónico para Iniciar Sesión', // Subject line
        text: `Hola,\n\nHas solicitado iniciar sesión y se requiere verificación por correo electrónico.\n\nPor favor, haz clic en el siguiente enlace o cópialo en tu navegador para verificar tu identidad:\n\n${verificationLink}\n\nEste enlace expirará pronto.\n\nSi no solicitaste esto, por favor ignora este correo.`, // Plain text body
        html: `<p>Hola,</p><p>Has solicitado iniciar sesión y se requiere verificación por correo electrónico.</p><p>Por favor, haz clic en el siguiente enlace para verificar tu identidad:</p><p><a href="${verificationLink}">Verificar Correo Electrónico</a></p><p>Este enlace expirará pronto.</p><p>Si no solicitaste esto, por favor ignora este correo.</p>`, // HTML body
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Correo de verificación enviado: %s', info.messageId);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error('Error al enviar correo de verificación:', error);
        throw new Error('Error al enviar el correo de verificación.');
    }
};*/

