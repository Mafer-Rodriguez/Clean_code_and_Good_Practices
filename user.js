const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../config/config').get(process.env.NODE_ENV);

const SALT_ROUNDS = 10;
const TOKEN_EXPIRATION = '1h';
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const userSchema = new mongoose.Schema(
    {
        email: {
            type: String,
            required: true,
            trim: true,
            lowercase: true,
            unique: true,
            match: [EMAIL_REGEX, 'El email no es válido']
        },
        password: {
            type: String,
            required: true,
            minlength: 6
        },
        firstname: {
            type: String,
            trim: true,
            maxlength: 100
        },
        lastname: {
            type: String,
            trim: true,
            maxlength: 100
        },
        token: {
            type: String
        }
    },
    {
        timestamps: true,
        toJSON: {
            // Nunca exponer datos sensibles en las respuestas
            transform: (doc, ret) => {
                delete ret.password;
                delete ret.token;
                return ret;
            }
        }
    }
);

// Encriptar la contraseña antes de guardar el usuario
userSchema.pre('save', async function () {
    if (!this.isModified('password')) return;
    this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
});

// Comparar la contraseña recibida en el login con la guardada
userSchema.methods.comparePassword = function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

// Generar un token JWT, guardarlo en el usuario y devolver el usuario actualizado
userSchema.methods.generateToken = function () {
    this.token = jwt.sign(
        { id: this._id.toHexString() },
        config.SECRET,
        { expiresIn: TOKEN_EXPIRATION }
    );
    return this.save();
};

// Buscar al usuario dueño de un token válido (null si es inválido o expiró)
userSchema.statics.findByToken = async function (token) {
    try {
        const decoded = jwt.verify(token, config.SECRET);
        return await this.findOne({ _id: decoded.id, token });
    } catch (err) {
        return null;
    }
};

// Eliminar el token al cerrar sesión
userSchema.methods.deleteToken = function () {
    this.token = undefined;
    return this.save();
};

const User = mongoose.model('User', userSchema);

module.exports = User;
