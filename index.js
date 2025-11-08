import express from 'express'; //Import express
import cors from 'cors'; //Import cors para conectar frontend con backend

import { join, dirname } from 'path'; //Import dirname
import { fileURLToPath } from 'url'; //Import fileURLToPath

import routes from "./routes/indexroutes.js"//Importin the routes
//import cookieParser from 'cookie-parser';
import session from 'express-session'; 
import passport from 'passport';
import dotenv from 'dotenv'; //Import dotenv to use environment variables


import "./strategies/local-strategy.js"; //Import local strategy

//Desabilitada para q no de conflicto con la estrategia local
//import "./strategies/github-strategy.js"; //Import github-strategy 
//import "./strategies/google-strategy.js"; //Import google-strategy 


import SequelizeStore from 'connect-session-sequelize';
import sequelize from './databases/connection.js'; //Import sequelize instance

//Fetchin environment variables
dotenv.config(); //Load environment variables from .env file

//Initialization express
const app = express(); 

//Configure cors to allow requests from localhost:3000
const allowedOrigins = [
    process.env.FRONTEND_URL, // Ej: http://localhost:5173
    `http://<TU_IP_LOCAL>:${process.env.FRONTEND_PORT || 5173}` // Reemplaza con tu IP y puerto
];

// Para desarrollo, podrías querer agregar la IP de tu máquina dinámicamente
if (process.env.NODE_ENV !== 'production') {
    // Aquí puedes añadir la IP de tu red local para que tu móvil pueda conectarse
    // Por ejemplo: 'http://192.168.1.5:5173'
    // Puedes encontrar tu IP con 'ipconfig' (Windows) o 'ifconfig' (Mac/Linux)
    const localIpUrl = 'http://192.168.121.9:5173'; // ¡CAMBIA ESTO POR TU IP REAL!
    allowedOrigins.push(localIpUrl);
}


app.use(cors({
    origin: function (origin, callback) {
        // Permitir solicitudes sin origen (como Postman o apps móviles)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'La política de CORS para este sitio no permite acceso desde el origen especificado.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true,
}));
// Configura el almacenamiento de sesiones con Sequelize
const SessionStore = SequelizeStore(session.Store);
const sequelizeStore = new SessionStore({
    db: sequelize,
});

// Sincroniza el modelo de sesiones con la base de datos

sequelizeStore.sync();


//Set port to 3000 or use the port from the environment variable
const port = process.env.PORT || 3000; 

//Get the directory name of the current module
const __dirname = dirname(fileURLToPath(import.meta.url)); 

//Middleware
app.use(express.json()); //look requests where the Content-Type header matches the type option.
//app.use(cookieParser("mysignedcookie")); //Parse cookies in the request before our routes

app.use(
    session({
        secret: process.env.SESSION_SECRET || "erick the dev",
        resave: false,
        saveUninitialized: false,
        store: sequelizeStore,
        cookie: {
            maxAge: 24 * 60 * 60 * 1000, // 1 día
            // EN PRODUCCIÓN, ESTO DEBE SER 'true' Y USAR HTTPS
            secure: process.env.NODE_ENV === 'production',
            
            // ESTO ES CLAVE PARA ENTORNOS NO-HTTPS Y CROSS-SITE
            // PERO CUIDADO EN PRODUCCIÓN
            sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax'
        },
    })
);

if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1); 
}

//app.set("views", join(__dirname, "views")); //Set views directory
//app.set("view engine", "ejs"); //Set view engine to ejs

app.use(passport.initialize()); //Initialize passport
app.use(passport.session());//Initialize passport session atach a user object to session
app.use(routes) //Defining the routes that came from the routes file

//app.use(express.urlencoded({ extended: true }));//If we are working with forms, we need to parse the body of the request
// Public files use for everyone
//app.use(express.static(join(__dirname, "public"))); //Set public directory


//Run Server
app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});

//Routes
app.get("/", (req, res)=>{

    res.send({mensaje: "Estoy en express"}); //Send a json response
})

/*app.get("/every", (req,res) => {
    res.sendFile("every.html", { root: join(__dirname, "public") }); //Send every.html file
})*/
