import { DataTypes } from "sequelize";
import sequelize from "../connection.js"; //Import sequelize instance

const Role = { USER: "user", ADMIN: "admin" };

const User = sequelize.define(
    "User",
    {
        name: {
            type: DataTypes.STRING,
            allowNull: false,
            validate: {
                len: [3, 50], // Name must be between 3 and 50 characters
            },
        },
        email: {
            type: DataTypes.STRING,
            allowNull: false,
            unique: true,
            validate: {
                isEmail: true,
            },
        },
        password: {
            type: DataTypes.STRING,
            allowNull: true,
            unique: true,
        },
        googleId:{
            type: DataTypes.STRING,
            allowNull: true,
            unique: true,
        },
        githubId:{
            type: DataTypes.STRING,
            allowNull: true,
            unique: true,
        },
        otp:{
            type: DataTypes.STRING,
            allowNull: true,    
        },
        otpExpiry:{
            type: DataTypes.DATE,
            allowNull: true,
        },
        isVerified:{
            type: DataTypes.BOOLEAN,
            allowNull: false, 
            defaultValue:false,   
        },
        resetPasswordToken: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        resetPasswordExpiry: {
            type: DataTypes.DATE,
            allowNull: true,
        },
        role:{
            type: DataTypes.ENUM(Role.USER, Role.ADMIN),
            allowNull: false,
            defaultValue: Role.USER,
        },
        emailVerificationToken: { // New field
            type: DataTypes.STRING,
            allowNull: true,
          },
          emailVerificationExpiry: { // New field
            type: DataTypes.DATE,
            allowNull: true,
          },
        
    },
    {
        tableName: "users", // Especifica el nombre de la tabla
    }
)


// Export the User model
export default User;