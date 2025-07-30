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

    // Admin Configuration
    admin: {
        username: process.env.ADMIN_USERNAME || 'admin',
        password: process.env.ADMIN_PASSWORD || 'admin123'
    },

    // Cloudinary Configuration
    cloudinary: {
        cloudName: process.env.CLOUDINARY_CLOUD_NAME,
        apiKey: process.env.CLOUDINARY_API_KEY,
        apiSecret: process.env.CLOUDINARY_API_SECRET,
        uploadPreset: process.env.CLOUDINARY_UPLOAD_PRESET || 'educycle_unsigned'
    },

    // Email Configuration
    email: {
        host: process.env.EMAIL_HOST,
        port: parseInt(process.env.EMAIL_PORT) || 587,
        secure: process.env.EMAIL_SECURE === 'true',
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
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
        'SESSION_SECRET',
        'CLOUDINARY_CLOUD_NAME',
        'CLOUDINARY_API_KEY',
        'CLOUDINARY_API_SECRET'
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

    // Validate Cloudinary configuration
    if (!config.cloudinary.cloudName || !config.cloudinary.apiKey || !config.cloudinary.apiSecret) {
        console.error('❌ Error: Cloudinary configuration is incomplete');
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
    console.log('✅ Cloudinary configuration loaded');
};

module.exports = {
    config,
    validateConfig
};
