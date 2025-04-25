const { DataTypes } = require('sequelize');

module.exports = model;

// This function defines the Account model for the database using Sequelize ORM.
function model(sequelize) {

    // Define the attributes for the Account model.
    // It includes various attributes such as email, passwordHash, title, firstName, lastName, etc.
    const attributes = {
        email: { type: DataTypes.STRING, allowNull: false },
        passwordHash: { type: DataTypes.STRING, allowNull: false },
        title: { type: DataTypes.STRING, allowNull: false },
        firstName: { type: DataTypes.STRING, allowNull: false },
        lastName: { type: DataTypes.STRING, allowNull: false },
        acceptTerms: { type: DataTypes.BOOLEAN },
        role: { type: DataTypes.STRING, allowNull: false },
        verificationToken: { type: DataTypes.STRING },
        verified: { type: DataTypes.DATE },
        resetToken: { type: DataTypes.STRING },
        resetTokenExpires: { type: DataTypes.DATE },
        passwordReset: { type: DataTypes.DATE },
        created: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
        updated: { type: DataTypes.DATE },
        isVerified: {
            type: DataTypes.VIRTUAL,
            get() { return !!(this.verified || this.passwordReset); }
        }
    };

    // Define the options for the Account model.
    const options = {
        timestamps: false, // Disable automatic timestamps
        defaultScope: {
            attributes: { exclude: ['passwordHash'] } // Exclude passwordHash by default
        },
        scopes: {
            withHash: { attributes: {} }
        }
    };

    return sequelize.define('account', attributes, options);
}