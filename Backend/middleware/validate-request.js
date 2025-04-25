module.exports = validateRequest;

// This middleware validates the request body against a given Joi schema.
function validateRequest(req, next, schema) {
    const options = {
        // abortEarly: false will return all validation errors, not just the first one
        abortEarly: false,
        // allowUnknown: true will allow properties not defined in the schema
        allowUnknown: true,
        // stripUnknown: true will remove properties not defined in the schema
        stripUnknown: true
    };
    const { error, value } = schema.validate(req.body, options);

    // If there is an error, send a validation error message
    if (error) {
        next(`Validation error: ${error.details.map(x => x.message).join(', ')}`);
    } else {
        req.body = value;
        next();
    }
}