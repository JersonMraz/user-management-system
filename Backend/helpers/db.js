const config = require('../config.json');
const mysql = require('mysql2/promise');
const { Sequelize } = require('sequelize');

module.exports = db = {};

initialize();

async function initialize() {
    try {
        const { host, port, user, password, database } = config.database;
        
        // Create connection to MySQL server by using mysql2/promise
        const connection = await mysql.createConnection({ 
            host, 
            port, 
            user, 
            password,
            insecureAuth: true // Allow insecure auth for MySQL 5.7 and below
        });
        
        // Create database if not exists
        await connection.query(`CREATE DATABASE IF NOT EXISTS \`${database}\`;`);
        await connection.end();

        // Connect Sequelize
        const sequelize = new Sequelize(database, user, password, { 
            host,
            dialect: 'mysql',
            dialectOptions: {
                connectTimeout: 10000
            },
            logging: console.log // To debug and to see SQL queries in browser console
        });

        // Initialize models
        db.Account = require('../accounts/account.model')(sequelize);
        db.RefreshToken = require('../accounts/refresh-token.model')(sequelize);

        db.Account.hasMany(db.RefreshToken, { onDelete: 'CASCADE' });
        db.RefreshToken.belongsTo(db.Account);

        // Synchronize models
        await sequelize.authenticate();
        await sequelize.sync({ alter: true });
        console.log('Database synchronized');
        
    } catch (err) {
        console.error('Database initialization failed:', err);
        process.exit(1);
    }
}