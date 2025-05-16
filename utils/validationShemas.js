// e:\5CursoNodeJS-Express\1ExpressJs\MultifactorAutentication\FrontEnd + Backend + Multifactor\ExpressPostgreSQL\utils\validationShemas.js

const Role = { USER: "user", ADMIN: "admin" };

export const createUserValidationShema = {
    name: {
        isString: true,
        exists: { errorMessage: "Name is required" },
        isLength: {
            options: { min: 3, max: 50 },
            errorMessage: "Name must be between 3 and 50 characters",
        },
    },
    email: {
        isEmail: true,
        exists: { errorMessage: "Email is required" },
        errorMessage: "Invalid email format",
    },
    password: {
        isString: true,
        exists: { errorMessage: "Password is required" },
        isLength: {
            options: { min: 6 },
            errorMessage: "Password must be at least 6 characters long",
        },
    },
    role: {
        optional: true, // Admin can optionally set a role, defaults to 'user' in model
        isString: true,
        isIn: {
            options: [[Role.USER, Role.ADMIN]],
            errorMessage: `Role must be either '${Role.USER}' or '${Role.ADMIN}'`,
        }
    }
};

export const loginValidationUserShema = {
    email: {
        isEmail: true,
        exists: { errorMessage: "Email is required" },
        errorMessage: "Invalid email format",
    },
    password: {
        isString: true,
        exists: { errorMessage: "Password is required" },
    },
};

export const PatchUserValidationShema = {
    name: {
        optional: true,
        isString: true,
        isLength: {
            options: { min: 3, max: 50 },
            errorMessage: "Name must be between 3 and 50 characters",
        },
    },
    email: {
        optional: true,
        isEmail: true,
        errorMessage: "Invalid email format",
    },
    // Password updates should ideally be handled via a separate, more secure flow (e.g., "change password")
    // For admin updates, if password change is allowed here, ensure proper hashing.
    // password: {
    //     optional: true,
    //     isString: true,
    //     isLength: { options: { min: 6 }, errorMessage: "Password must be at least 6 characters" }
    // },
    role: {
        optional: true,
        isString: true,
        isIn: {
            options: [[Role.USER, Role.ADMIN]],
            errorMessage: `Role must be either '${Role.USER}' or '${Role.ADMIN}'`,
        }
    }
    // Add other fields that can be patched, e.g., isVerified
    // isVerified: {
    //     optional: true,
    //     isBoolean: true,
    //     errorMessage: "isVerified must be a boolean"
    // }
};

// Define PutUserValidationShema if needed, typically requires all fields.
export const PutUserValidationShema = {
    // ... similar to createUserValidationShema but all fields might be required
    // and 'id' should not be part of the body for a PUT on /users/:id
};

export const queryValidationUserShema = {
    filter: {
        optional: true,
        isString: true,
        isIn: {
            options: [['name']], // Example: only allow filtering by name
            errorMessage: "Invalid filter parameter. Allowed: name"
        }
    },
    value: {
        optional: true,
        isString: true,
        custom: {
            options: (value, { req }) => {
                if (req.query.filter && !value) {
                    throw new Error('Value is required when filter is provided');
                }
                return true;
            }
        }
    }
};

export const changePasswordValidationSchema = {
    oldPassword: {
        in: ['body'],
        notEmpty: {
            errorMessage: 'La contraseña anterior es requerida.',
        },
        isString: {
            errorMessage: 'La contraseña anterior debe ser una cadena de texto.',
        },
    },
    newPassword: {
        in: ['body'],
        notEmpty: {
            errorMessage: 'La nueva contraseña es requerida.',
        },
        isString: {
            errorMessage: 'La nueva contraseña debe ser una cadena de texto.',
        },
        isLength: {
            options: { min: 8 },
            errorMessage: 'La nueva contraseña debe tener al menos 8 caracteres.',
        },
        matches: {
            options: [/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).*$/],
            errorMessage: 'La nueva contraseña debe contener al menos una letra minúscula, una mayúscula, un número y un carácter especial.',
        },
    },
};