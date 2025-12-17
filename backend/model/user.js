const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

const userSchema = new mongoose.Schema(
    {
        name: { type: String, required: true, trim: true },
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
            match: [/.+@.+\..+/, 'Invalid email address']
        },
        password: { type: String, required: true, select: false },
        role: { type: String, enum: ['user', 'host', 'admin'], default: 'user' },
        avatar: { type: String, default: null },
        provider: { type: String, default: 'local' }, // e.g. local, google, facebook
        resetPasswordToken: String,
        resetPasswordExpires: Date
    },
    { timestamps: true }
);

// Hash password before save
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    try {
        const hash = await bcrypt.hash(this.password, SALT_ROUNDS);
        this.password = hash;
        next();
    } catch (err) {
        next(err);
    }
});

// Instance: compare plaintext password with hash
userSchema.methods.comparePassword = function (candidatePassword) {
    // this.password may be undefined if not selected; ensure caller selects password
    return bcrypt.compare(candidatePassword, this.password);
};

// Instance: generate JWT
userSchema.methods.generateJWT = function () {
    const payload = { id: this._id, role: this.role };
    return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

// Ensure password and sensitive fields are not returned
userSchema.methods.toJSON = function () {
    const obj = this.toObject();
    delete obj.password;
    delete obj.__v;
    return obj;
};

// Static: find by credentials (email + password)
userSchema.statics.findByCredentials = async function (email, password) {
    const user = await this.findOne({ email }).select('+password');
    if (!user) return null;
    const isMatch = await user.comparePassword(password);
    return isMatch ? user : null;
};

module.exports = mongoose.model('User', userSchema);