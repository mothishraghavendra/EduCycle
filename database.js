// database.js - Database connection adapter for both MySQL and PostgreSQL
const config = require('./config');

let db;

if (process.env.DATABASE_URL) {
    // PostgreSQL (Render)
    const { Pool } = require('pg');
    
    db = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });
    
    // Convert MySQL queries to PostgreSQL
    const originalQuery = db.query.bind(db);
    db.query = async (sql, params) => {
        // Convert MySQL ? placeholders to PostgreSQL $1, $2, etc.
        let pgSql = sql;
        let pgParams = params;
        
        if (params && params.length > 0) {
            pgSql = sql.replace(/\?/g, (match, offset) => {
                const paramIndex = sql.substring(0, offset).split('?').length;
                return `$${paramIndex}`;
            });
        }
        
        try {
            const result = await originalQuery(pgSql, pgParams);
            return [result.rows]; // Match MySQL format
        } catch (error) {
            throw error;
        }
    };
    
} else {
    // MySQL (Local/External)
    const mysql = require('mysql2/promise');
    
    db = mysql.createPool({
        host: config.db.host,
        user: config.db.user,
        password: config.db.password,
        database: config.db.name,
        connectionLimit: config.db.connectionLimit,
        queueLimit: config.db.queueLimit,
        acquireTimeout: 60000,
        timeout: 60000,
        reconnect: true
    });
}

module.exports = db;
