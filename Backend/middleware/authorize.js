const { expressjwt: jwt } = require("express-jwt");
const { secret } = require('../config.json');
const db = require('../helpers/db');

module.exports = authorize;

function authorize(roles = []) {
    if (typeof roles === 'string') {
        roles = [roles];
    }

    return [
        // JWT middleware to check token
        jwt({
            secret,
            algorithms: ['HS256'],
            credentialsRequired: true,
            requestProperty: 'auth' // Attach token to request object
        }),

        // Middleware to check if user is authenticated and authorized
        async (req, res, next) => {
            try {
                // Check if token is present and valid
                if (!req.auth || !req.auth.id) {
                    return res.status(401).json({ message: 'Invalid token' });
                }
                // Find the account associated with the token
                const account = await db.Account.findByPk(req.auth.id);        
                if (!account) {
                    return res.status(401).json({ message: 'Account not found' });
                }
                
                // Check if the user has the required role
                if (roles.length && !roles.includes(account.role)) {
                    return res.status(401).json({ message: 'Insufficient permissions' });
                }

                // Attach user information to the request object
                req.user = {
                    id: account.id,
                    role: account.role,
                    // Add any other user properties you want to expose
                    ownsToken: async (token) => {
                        const refreshTokens = await account.getRefreshTokens();
                        return refreshTokens.some(x => x.token === token);
                    }
                };
                next();
            } catch (err) {
                next(err);
            }
        }
    ];
}