import { Sequelize } from 'sequelize';

// Configura Sequelize con PostgreSQL
const sequelize = new Sequelize(process.env.DATABASE_URL , {
    dialect: 'postgres',
    logging: false, // Desactiva el logging de consultas SQL
    dialectOptions: {
        ssl: {
            require: true,
            // rejectUnauthorized: true // Por defecto es true.
            // Clever Cloud debería usar certificados válidos,
            // por lo que no deberías necesitar ponerlo en false.
            // Cambiar a false solo si es estrictamente necesario y entiendes los riesgos de seguridad.
        }
    }
});

// Sincroniza los modelos con la base de datos
sequelize
    .sync({ force: false }) // Cambia a `true` si quieres recrear las tablas (¡esto elimina los datos existentes!)
    .then(() => {
        console.log('Base de datos sincronizada correctamente');
    })
    .catch((error) => {
        console.error('Error al sincronizar la base de datos:', error);
    });

sequelize
    .authenticate()
    .then(() => console.log('Conexión a PostgreSQL exitosa'))
    .catch((error) => console.error('Error al conectar a PostgreSQL:', error));

export default sequelize;