const config = require('config.json');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require("crypto");
const { Op } = require('sequelize');
const sendEmail = require('../helpers/send-email');
const db = require('../helpers/db');
const Role = require('../helpers/role');

module.exports = {
    authenticate,
    refreshToken,
    revokeToken,
    register,
    verifyEmail,
    forgotPassword,
    validateResetToken,
    resetPassword,
    getAll,
    getById,
    createAccount,
    updateAccount,
    deleteAccount
};


async function authenticate({ email, password, ipAddress }) {
    // Find the account in database, including the password hash (normally hidden)
    const account = await db.Account.scope('withHash').findOne({ where: { email } });

    // Check if: 
    // 1. Account exists 
    // 2. Account is verified 
    // 3. Password matches the hash
    // If any check fails, throw an error
    if (!account || !account.isVerified || !(await bcrypt.compare(password, account.passwordHash))) {
        throw 'Email or password is incorrect';
    }

    // If we get here, the login is successful!
    
    // 1. Create a short-lived JWT token (typically expires in 15-30 mins)
    const jwtToken = generateJwtToken(account);
    
    // 2. Create a long-lived refresh token (typically expires in 7 days)
    const refreshToken = generateRefreshToken(account, ipAddress);

    // Save the refresh token in database so we can verify it later
    await refreshToken.save();

    // Return the account info plus both tokens to the client
    return {
        ...basicDetails(account),  // Basic account info (id, name, email, etc.)
        jwtToken,                 // Short-lived access token
        refreshToken: refreshToken.token  // Long-lived token for getting new access tokens
    };
}

async function refreshToken({ token, ipAddress }) {
    // 1. Find the existing refresh token in the database
    const refreshToken = await getRefreshToken(token);
    
    // 2. Get the account associated with this refresh token
    const account = await refreshToken.getAccount();

    // Refresh token rotation - security best practice:
    // a) Create a brand new refresh token
    const newRefreshToken = generateRefreshToken(account, ipAddress);
    
    // b) Mark the old token as revoked (with timestamp and IP that revoked it)
    refreshToken.revoked = Date.now();  // When it was revoked
    refreshToken.revokedByIp = ipAddress;  // Which IP revoked it
    refreshToken.replacedByToken = newRefreshToken.token;  // What token replaced it
    
    // c) Save both tokens to database
    await refreshToken.save();
    await newRefreshToken.save();

    // 3. Generate a fresh JWT access token (short-lived)
    const jwtToken = generateJwtToken(account);

    // 4. Return the account info plus new tokens to client
    return {
        ...basicDetails(account),  // Basic account info (id, name, email, etc.)
        jwtToken,                // New short-lived access token (typically 15-30 mins)
        refreshToken: newRefreshToken.token  // New long-lived refresh token (typically 7 days)
    };
}

async function revokeToken({ token, ipAddress }) {
    // 1. Find the refresh token in the database using the provided token string
    const refreshToken = await getRefreshToken(token);

    // 2. Revoke the token by:
    //    - Setting revocation timestamp (when it was revoked)
    //    - Recording which IP address performed the revocation
    refreshToken.revoked = Date.now();         // Current time in milliseconds since epoch
    refreshToken.revokedByIp = ipAddress;      // IP address of the client revoking the token

    // 3. Save the updated token to the database
    //    This ensures the token can't be used again (it's now marked as revoked)
    await refreshToken.save();

    // Note: No return value needed - this is a "fire and forget" operation
    // The client will know revocation succeeded if this doesn't throw an error
}

async function register(params, origin) {
    // Check if email is already registered (prevent duplicate accounts)
    if (await db.Account.findOne({ where: { email: params.email } })) {
        // Security measure: Instead of showing an error, send an email
        return await sendAlreadyRegisteredEmail(params.email, origin);
    }

    // Create new account with user's registration data
    const account = new db.Account(params);
    
    // Special rule: First user becomes admin, others get user role
    // This ensures the system always has at least one admin account
    const isFirstAccount = (await db.Account.count()) === 0;
    account.role = isFirstAccount ? Role.Admin : Role.User;
    
    // Generate a secure random token for email verification
    account.verificationToken = randomTokenString();
    
    // Important security step: Hash the password before storing
    // Never store passwords in plain text!
    account.passwordHash = await hash(params.password);
    
    // Save the new account to the database
    await account.save();
    
    // Send verification email with confirmation link
    await sendVerificationEmail(account, origin);
}

async function verifyEmail({ token }) {
    // Find account with matching verification token
    // (This token was sent to the user's email during registration)
    const account = await db.Account.findOne({ where: { verificationToken: token } });
    
    // If no account found with this token, verification fails
    // (Token might be invalid or expired)
    if (!account) throw 'Verification failed';
    
    // Mark account as verified by:
    // 1. Setting verification timestamp (when email was confirmed)
    account.verified = Date.now();
    // 2. Clearing the verification token (it can't be used again)
    account.verificationToken = null;
    
    // Save the updated account status to database
    await account.save();
    
    // Note: No return value needed - frontend should show success message
    // if this completes without throwing an error
}

async function forgotPassword({ email }, origin) {
    const account = await db.Account.findOne({ where: { email } });
    
    // always return ok response to prevent email enumeration
    if (!account) return;
    
    // create reset token that expires after 24 hours
    account.resetToken = randomTokenString();
    account.resetTokenExpires = new Date(Date.now() + 24*60*60*1000);
    await account.save();
    
    // send email
    await sendPasswordResetEmail(account, origin);
}

async function validateResetToken({ token }) {
    const account = await db.Account.findOne({
        where: {
            resetToken: token,
            resetTokenExpires: { [Op.gt]: Date.now() }
        }
    });

    if (!account) throw 'Invalid token';

    return account;
}

async function resetPassword({ token, password }) {
    const account = await validateResetToken({ token });

    account.passwordHash = await hash(password);
    account.passwordReset = Date.now();
    account.resetToken = null;
    account.resetTokenExpires = null;
    await account.save();
}

async function getAll() {
    const accounts = await db.Account.findAll();
    return accounts.map(x => basicDetails(x));
}

async function getById(id) {
    const account = await getAccount(id);
    return basicDetails(account);
}

async function createAccount(params) {
    // validate
    if (await db.Account.findOne({ where: { email: params.email } })) {
        throw 'Email "' + params.email + '" is already registered';
    }

    const account = new db.Account(params);
    account.verified = Date.now();
    // hash password
    account.passwordHash = await hash(params.password);
    // save account
    await account.save();
    return basicDetails(account);
}

async function updateAccount(id, params) {
    const account = await getAccount(id);
    // validate (if email was changed)
    if (params.email && account.email !== params.email && await db.Account.findOne({ where: { email: params.email } })) {
        throw 'Email "' + params.email + '" is already taken';
    }

    // hash password if it was entered
    if (params.password) {
        params.passwordHash = await hash(params.password);
    }

    // copy params to account and save
    Object.assign(account, params);
    account.updated = Date.now();
    await account.save();
    return basicDetails(account);
}

async function deleteAccount(id) {
    const account = await getAccount(id);
    await account.destroy();
}

async function getAccount(id) {
    const account = await db.Account.findByPk(id);
    if (!account) throw 'Account not found';
    return account;
}

async function getRefreshToken(token) {
    const refreshToken = await db.RefreshToken.findOne({ where: { token } });
    if (!refreshToken || !refreshToken.isActive) throw 'Invalid token';
    return refreshToken;
}

async function hash(password) {
    return await bcrypt.hash(password, 10);
}

function generateJwtToken(account) {
    // create a jwt token containing the account id that expires in 15 minutes
    return jwt.sign({ sub: account.id, id: account.id }, config.secret, { expiresIn: '15m' });
}

function generateRefreshToken(account, ipAddress) {
    // create a refresh token that expires in 7 days
    return new db.RefreshToken({
        accountId: account.id,
        token: randomTokenString(),
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        createdByIp: ipAddress
    });
}

function randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
}

function basicDetails(account) {
    const { id, title, firstName, lastName, email, role, created, updated, isVerified } = account;
    return { id, title, firstName, lastName, email, role, created, updated, isVerified };
}

function generateJwtToken(account) {
    // Include both sub and id claims for compatibility
    return jwt.sign(
        {
            sub: account.id,  // Standard JWT claim
            id: account.id,   // Duplicate for easier access
            role: account.role // Include role for authorization
        },
        config.secret,
        { expiresIn: '15m' }
    );
}

async function sendVerificationEmail(account, origin) {
    let message;
    if (origin) {
        const verifyUrl = `${origin}/account/verify-email?token=${account.verificationToken}`;
        message = `<p>Please click the below link to verify your email address</p>
                   <p><a href="${verifyUrl}">${verifyUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to verify your email address with the <code>/account/verify-email</code> api route</p>
                   <p><code>${account.verificationToken}</code></p>`;
    }
    await sendEmail({
        to: account.email,
        subject: 'Sign-up Verification API - Verify Email',
        html: `<h4>Verify Email</h4>
               <p>Thanks for registering!</p>
               ${message}`
    });
}


async function sendPasswordResetEmail(account, origin) {
    let message;
    if (origin) {
        const resetUrl = `${origin}/account/reset-password?token=${account.resetToken}`;
        message = `<p>Please click the below link to reset your password, the link will be valid for 1 day!</p>
                   <p><a href="${resetUrl}">${resetUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to reset your password with the <code>/account/reset-password</code> api route</p>
                   <p><code>${account.resetToken}</code></p>`;
    }
    await sendEmail({
        to: account.email,
        subject: 'Sign-up Verification API - Reset Password',
        html: `<h4>Verify Email</h4>
               ${message}`
    });
}