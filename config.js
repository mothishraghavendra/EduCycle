// Configuration management module
require('dotenv').config();

const config = {
    // Server Configuration
    server: {
        port: process.env.PORT || 8080,
        host: process.env.HOST || 'localhost',
        environment: process.env.NODE_ENV || 'development'
    },

    // Database Configuration
    database: {
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME || 'educycle',
        connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT) || 10,
        queueLimit: parseInt(process.env.DB_QUEUE_LIMIT) || 0,
        waitForConnections: true
    },

    // Session Configuration
    session: {
        name: process.env.SESSION_NAME || 'educycle_session',
        secret: process.env.SESSION_SECRET,
        maxAge: parseInt(process.env.SESSION_MAX_AGE) || 86400000, // 24 hours
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true
    },

    // Security Configuration
    security: {
        bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12
    },

    // Application Configuration
    app: {
        name: process.env.APP_NAME || 'Educycle',
        version: process.env.APP_VERSION || '1.0.0'
    },

    // Feature Flags
    features: {
        enableLogging: process.env.ENABLE_LOGGING !== 'false',
        enableCors: process.env.ENABLE_CORS === 'true',
        enableHttps: process.env.ENABLE_HTTPS === 'true'
    }
};

// Validation function
const validateConfig = () => {
    const requiredVars = [
        'DB_PASSWORD',
        'SESSION_SECRET'
    ];

    const missing = requiredVars.filter(varName => !process.env[varName]);
    
    if (missing.length > 0) {
        console.error('❌ Error: Missing required environment variables:');
        missing.forEach(varName => console.error(`   - ${varName}`));
        console.error('💡 Please check your .env file and ensure all required variables are set.');
        process.exit(1);
    }

    // Validate database password
    if (!config.database.password) {
        console.error('❌ Error: Database password is required');
        process.exit(1);
    }

    // Validate session secret
    if (!config.session.secret) {
        console.error('❌ Error: Session secret is required');
        process.exit(1);
    }

    // Warn about production settings
    if (config.server.environment === 'production') {
        if (config.session.secret.length < 32) {
            console.warn('⚠️  Warning: Session secret should be at least 32 characters long in production');
        }
        
        if (!config.session.secure) {
            console.warn('⚠️  Warning: Session cookies should be secure in production (HTTPS required)');
        }
    }

    console.log('✅ Configuration validated successfully');
};

module.exports = {
    config,
    validateConfig
};
