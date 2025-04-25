const express = require('express');
const router = express.Router();
const Joi = require('joi');
const validateRequest = require('../middleware/validate-request');
const authorize = require('../middleware/authorize');
const Role = require('../helpers/role');
const accountService = require('./account.service');

// routes
router.post('/authenticate', authenticateSchema, authenticate);
router.post('/refresh-token', refreshToken);
router.post('/revoke-token', authorize(), revokeTokenSchema, revokeToken);
router.post('/register', registerSchema, register);
router.post('/verify-email', verifyEmailSchema, verifyEmail);
router.post('/forgot-password', forgotPasswordSchema, forgotPassword);
router.post('/validate-reset-token', validateResetTokenSchema, validateResetToken);
router.post('/reset-password', resetPasswordSchema, resetPassword);
router.get('/', authorize(Role.Admin), getAll);
router.get('/:id', authorize(), getById);
router.post('/', authorize(Role.Admin), createSchema, create);
router.put('/:id', authorize(), updateSchema, update);
router.delete('/:id', authorize(), deleteAccount);

module.exports = router;

function authenticateSchema(req, res, next) {
    const schema = Joi.object({
        email: Joi.string().required(),
        password: Joi.string().required()
    });
    validateRequest(req, next, schema);
}

function authenticate(req, res, next) {
    const { email, password } = req.body;
    const ipAddress = req.ip;
    accountService.authenticate({ email, password, ipAddress })
        .then(({ refreshToken, ...account }) => {
            setTokenCookie(res, refreshToken);
            res.json({
                ...account,
                id: account.id 
            });
        })
        .catch(next);
}

function refreshToken(req, res, next) {
    // 1. Get refresh token from HTTP-only cookie (secure storage)
    const token = req.cookies.refreshToken;
    
    // 2. Get client's IP address for security tracking
    const ipAddress = req.ip;
    
    // 3. Call account service to handle the token refresh logic
    accountService.refreshToken({ token, ipAddress })
        .then(({ refreshToken, ...account }) => {
            // 4. On success:
            //    - Set new refresh token in HTTP-only cookie
            //    - Return account data with new access token
            setTokenCookie(res, refreshToken);
            res.json(account);
        })
        .catch(next); // 5. Forward any errors to error handler
}

function revokeTokenSchema(req, res, next) {
    // Define validation schema:
    // - token: Optional string that can be empty
    const schema = Joi.object({
        token: Joi.string().empty('')
    });

    // Validate the request against the schema
    // - Proceeds to next middleware if valid
    // - Automatically handles errors if invalid
    validateRequest(req, next, schema);
}

function revokeToken(req, res, next) {
    // 1. Get token from either request body or HTTP-only cookie
    //    (Provides flexibility in how clients can send the token)
    const token = req.body.token || req.cookies.refreshToken;
    
    // 2. Get client's IP address for security logging
    const ipAddress = req.ip;

    // 3. Validate token exists
    if (!token) {
        return res.status(400).json({ message: 'Token is required' });
    }

    // 4. Authorization check:
    //    - Users can only revoke their own tokens
    //    - Admins can revoke any tokens
    if (!req.user.ownsToken(token) && req.user.role !== Role.Admin) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    // 5. Call account service to perform revocation
    accountService.revokeToken({ token, ipAddress })
        .then(() => {
            // Success response
            res.json({ message: 'Token revoked' });
        })
        .catch(next); // Forward errors to error handler
}
function registerSchema(req, res, next) {
    // Define validation rules for registration fields:
    const schema = Joi.object({
        // Personal information
        title: Joi.string().required(),                 // Required string (Mr, Mrs, etc.)
        firstName: Joi.string().required(),            // Required string
        lastName: Joi.string().required(),             // Required string
        
        // Account credentials
        email: Joi.string().email().required(),        // Must be valid email format
        password: Joi.string().min(6).required(),      // Minimum 6 characters
        confirmPassword: Joi.string()                  // Must match 'password' field
            .valid(Joi.ref('password')).required(),    // and is required
        
        // Legal requirement
        acceptTerms: Joi.boolean()                     // Must be exactly true
            .valid(true).required()                    // and is required
    });

    // Validate the request body against the schema
    // - Proceeds to next middleware if validation passes
    // - Automatically returns 400 error if validation fails
    validateRequest(req, next, schema);
}

function register(req, res, next) {
    // Call the account service to handle registration:
    // 1. Passes the registration data from request body
    // 2. Includes the origin URL (for email verification links)
    accountService.register(req.body, req.get('origin'))
        .then(() => {
            // On successful registration:
            // - Return success message
            // - Don't return sensitive data
            res.json({ 
                message: 'Registration successful, please check your email for verification instructions' 
            });
        })
        .catch(next); // Forward any errors to the error handler
}

function verifyEmailSchema(req, res, next) {
    // Define validation schema for email verification:
    // - token: Required string (the verification token sent to user's email)
    const schema = Joi.object({
        token: Joi.string().required()
    });

    // Validate the request against the schema
    // - Continues to next middleware if valid
    // - Returns 400 error if token is missing/invalid
    validateRequest(req, next, schema);
}

function verifyEmail(req, res, next) {
    // Call account service to verify the email using the token from request body
    accountService.verifyEmail(req.body)
        .then(() => {
            // On successful verification:
            // Return success message indicating user can now login
            res.json({ 
                message: 'Verification successful, you can now login' 
            });
        })
        .catch(next); // Forward any errors to the error handler
}

function forgotPasswordSchema(req, res, next) {
    const schema = Joi.object({
        email: Joi.string().email().required()
    });
    validateRequest(req, next, schema);
}

function forgotPassword(req, res, next) {
    accountService.forgotPassword(req.body, req.get('origin'))
        .then(() => res.json({ message: 'Please check your email for password reset instructions' }))
        .catch(next);
}

function validateResetTokenSchema(req, res, next) {
    const schema = Joi.object({
        token: Joi.string().required()
    });
    validateRequest(req, next, schema);
}

function validateResetToken(req, res, next) {
    accountService.validateResetToken(req.body)
        .then(() => res.json({ message: 'Token is valid' }))
        .catch(next);
}

function resetPasswordSchema(req, res, next) {
    const schema = Joi.object({
        token: Joi.string().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required()
    });
    validateRequest(req, next, schema);
}

function resetPassword(req, res, next) {
    accountService.resetPassword(req.body)
        .then(() => res.json({ message: 'Password reset successful, you can now login' }))
        .catch(next);
}

function getAll(req, res, next) {
    accountService.getAll()
        .then(accounts => res.json(accounts))
        .catch(next);
}

function getById(req, res, next) {
    // users can get their own account and admins can get any account
    if (Number(req.params.id) !== req.user.id && req.user.role !== Role.Admin) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    accountService.getById(req.params.id)
        .then(account => account ? res.json(account) : res.sendStatus(404))
        .catch(next);
}

function createSchema(req, res, next) {
    const schema = Joi.object({
        title: Joi.string().required(),
        firstName: Joi.string().required(),
        lastName: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
        role: Joi.string().valid(Role.Admin, Role.User).required()
    });
    validateRequest(req, next, schema);
}

function create(req, res, next) {
    accountService.create(req.body)
        .then(account => res.json(account))
        .catch(next);
}

function updateSchema(req, res, next) {
    const schemaRules = {
        title: Joi.string().empty(''),
        firstName: Joi.string().empty(''),
        lastName: Joi.string().empty(''),
        email: Joi.string().email().empty(''),
        password: Joi.string().min(6).empty(''),
        confirmPassword: Joi.string().valid(Joi.ref('password')).empty('')
    };

    // only admins can update role
    if (req.user.role === Role.Admin) {
        schemaRules.role = Joi.string().valid(Role.Admin, Role.User).empty('');
    }

    const schema = Joi.object(schemaRules).with('password', 'confirmPassword');
    validateRequest(req, next, schema);
}

function update(req, res, next) {
    // users can update their own account and admins can update any account
    if (Number(req.params.id) !== req.user.id && req.user.role !== Role.Admin) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    accountService.update(req.params.id, req.body)
        .then(account => res.json(account))
        .catch(next);
}

function deleteAccount(req, res, next) {
    // users can delete their own account and admins can delete any account
    if (Number(req.params.id) !== req.user.id && req.user.role !== Role.Admin) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    accountService.delete(req.params.id)
        .then(() => res.json({ message: 'Account deleted successfully' }))
        .catch(next);
}

// refresh token route
function setTokenCookie(res, token) {
    // Set the refresh token as a cookie in the response
    const cookieOptions = {
        httpOnly: true,
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // The cookie will be httpOnly and will expire in 7 days
    };
    res.cookie('refreshToken', token, cookieOptions);
}