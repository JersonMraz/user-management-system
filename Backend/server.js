require('rootpath')();
require('dotenv').config();

const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const errorHandler = require('./middleware/error-handler');

// Middleware to parse JSON and URL-encoded data
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// allow CORS from all origins
app.use(cors({ origin: (origin, callback) => callback(null, true), credentials: true }));

// Route for APIs
app.use('/accounts', require('./accounts/accounts.controller'));

// Route for swagger UI
app.use('/api-docs', require('./helpers/swagger'));

// global error handler
app.use(errorHandler);

const port = process.env.NODE_ENV === 'production' ? (process.env.PORT || 80) : 4000;
app.listen(port, () => console.log('Server listening on port ' + port));