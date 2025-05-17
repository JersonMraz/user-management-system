# Node.js + MySQL Backend System

## Introduction

This backend system is built with **Node.js** and **MySQL**, providing a secure and scalable foundation for user authentication, authorization, and account management. It is designed for applications that require verified user registration, role-based access control, and administrative tools for managing users. The architecture adheres to modern best practices for API security and maintainability.

---

## Features

### Email Sign-Up and Verification
- Users can register using their email address.
- A verification email is sent to confirm and activate the account.

### JWT Authentication with Refresh Tokens
- Secure login with **JSON Web Tokens (JWT)**.
- Short-lived access tokens and long-lived refresh tokens for seamless session management.

### Role-Based Authorization
- Two primary user roles:
  - **Admin**: Full access to all features.
  - **User**: Limited access to assigned resources.
- Route protection ensures only authorized roles can access specific endpoints.

### Password Recovery and Reset
- **Forgot Password**: Users can request a secure password reset link via email.
- **Reset Password**: Password updates are handled using time-limited tokens.

### Admin-Only Account Management (CRUD)
- Admin users can:
  - **Create** new user accounts.
  - **Read** and list user details.
  - **Update** account information.
  - **Delete** user accounts.

---

## Technologies Used

- **Node.js** (Express.js)
- **MySQL** (with MySQL2 or Sequelize ORM)
- **JWT** for authentication
- **Nodemailer** for email communication
- **dotenv** for environment variable management
- **bcrypt** for password hashing
---

## Setup & Installation

```bash
# Clone the repository
git https://github.com/JersonMraz/user-management-system.git
cd user-management-system.git

# Install dependencies
npm install bcryptjs body-parser cookie-parser cors express \
express-jwt joi jsonwebtoken mysql2 nodemailer sequelize \
swagger-ui-express yamljs

# Run the application
npm run dev