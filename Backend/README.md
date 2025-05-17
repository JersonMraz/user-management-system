# User Management System

## Overview
This is a Node.js and MySQL-based User Management System API that provides complete user authentication functionality including:

- User registration with email verification
- Authentication with JWT tokens and refresh tokens
- Password reset via email
- User account management (CRUD operations)
- Role-based authorization
- Secure API endpoints with JWT middleware

The system uses Express.js as the web framework, Sequelize as the ORM for MySQL database interactions, and includes Swagger documentation for API endpoints.

## Technologies Used
- Node.js
- Express.js
- MySQL
- Sequelize ORM
- JWT Authentication
- Nodemailer for email services
- Swagger for API documentation

## Prerequisites
- Node.js (v12 or higher)
- MySQL Server
- Git

## Installation

1. Clone the repository:
```
git clone <repository-url>
cd Backend
```

2. Install dependencies:
```
npm install
```

3. Configure the database:
   - Create a MySQL database named `node-mysql-signup-verification-api`
   - Update the database configuration in `config.json` if needed

4. Configure email settings:
   - Update the SMTP configuration in `config.json` for sending verification emails

## Running the Application

### Development Mode
```
npm run start:dev
```
This starts the server with nodemon for automatic reloading during development.

### Production Mode
```
npm start
```
The server will run on port 4000 by default in development mode, or port 80 in production mode.

## API Documentation
Once the server is running, you can access the Swagger API documentation at:
```
http://localhost:4000/api-docs
```

## API Endpoints

### Authentication
- POST `/accounts/authenticate` - Authenticate user credentials
- POST `/accounts/refresh-token` - Refresh JWT token
- POST `/accounts/revoke-token` - Revoke a refresh token

### Account Management
- POST `/accounts/register` - Register a new account
- POST `/accounts/verify-email` - Verify email address
- POST `/accounts/forgot-password` - Send password reset email
- POST `/accounts/reset-password` - Reset password
- GET `/accounts` - Get all accounts (admin only)
- GET `/accounts/{id}` - Get account by ID
- POST `/accounts` - Create a new account (admin only)
- PUT `/accounts/{id}` - Update an account
- DELETE `/accounts/{id}` - Delete an account

## Security Notes
- JWT tokens are used for API authentication
- Passwords are hashed using bcrypt
- Email verification is required before login
- Refresh tokens are stored in HTTP-only cookies

## Developer
This project was developed by [Your Name]

## License
This project is licensed under the MIT License.
