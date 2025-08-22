// Load environment variables and validate configuration
const { config, validateConfig } = require('./config');

// Validate configuration before starting
validateConfig();

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { sendWelcomeEmail, sendProductListingNotification, sendPasswordResetOTP } = require('./emailService');

const app = express();

// Configure Cloudinary
cloudinary.config({
    cloud_name: config.cloudinary.cloudName,
    api_key: config.cloudinary.apiKey,
    api_secret: config.cloudinary.apiSecret
});

// Configure multer for handling file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// Use configuration from config module
const PORT = config.server.port;
const HOST = config.server.host;
const NODE_ENV = config.server.environment;

// MySQL Database Configuration
const dbConfig = config.database;

// Create MySQL connection pool
const pool = mysql.createPool(dbConfig);
const promisePool = pool.promise();

// Session store configuration
const sessionStore = new MySQLStore(dbConfig);

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(__dirname));

// Session configuration
app.use(session({
    key: config.session.name,
    secret: config.session.secret,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: config.session.maxAge,
        secure: config.session.secure,
        httpOnly: config.session.httpOnly
    }
}));

// Database connection test
pool.getConnection((err, connection) => {
    if (err) {
        console.error('❌ Error connecting to MySQL database:', err.message);
        console.error('💡 Please check your database configuration in .env file');
        process.exit(1);
    }
    console.log('✅ Connected to MySQL database successfully!');
    connection.release();
});

// Create users table if it doesn't exist
const createUsersTable = async () => {
    try {
        const createTableQuery = `
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                email VARCHAR(255) NOT NULL UNIQUE,
                phone VARCHAR(20) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                location VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `;
        await promisePool.execute(createTableQuery);
    } catch (error) {
        console.error('❌ Error creating users table:', error);
    }
};

// Create products table if it doesn't exist
const createProductsTable = async () => {
    try {
        const createTableQuery = `
            CREATE TABLE IF NOT EXISTS products (
                product_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                name VARCHAR(100) NOT NULL,
                category VARCHAR(100),
                condition_item VARCHAR(100),
                description TEXT,
                price DECIMAL(10, 2) NOT NULL,
                image1 LONGBLOB,
                image2 LONGBLOB,
                image3 LONGBLOB,
                image1_url TEXT,
                image2_url TEXT,
                image3_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `;
        await promisePool.execute(createTableQuery);
        console.log('✅ Products table created/verified successfully with Cloudinary URL support');
    } catch (error) {
        console.error('❌ Error creating products table:', error);
    }
};

// Create sold_items table if it doesn't exist
const createSoldItemsTable = async () => {
    try {
        const createTableQuery = `
            CREATE TABLE IF NOT EXISTS sold_items (
                sold_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                original_product_id INT NOT NULL,
                name VARCHAR(100) NOT NULL,
                category VARCHAR(100),
                condition_item VARCHAR(100),
                description TEXT,
                price DECIMAL(10, 2) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                sold_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `;
        await promisePool.execute(createTableQuery);
    } catch (error) {
        console.error('❌ Error creating sold_items table:', error);
    }
};

// Create cart table if it doesn't exist
const createCartTable = async () => {
    try {
        const createTableQuery = `
            CREATE TABLE IF NOT EXISTS cart (
                cart_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                product_id INT NOT NULL,
                product_name VARCHAR(255) NOT NULL,
                product_price DECIMAL(10, 2) NOT NULL,
                product_category VARCHAR(100),
                product_condition VARCHAR(100),
                product_description TEXT,
                seller_id INT NOT NULL,
                seller_name VARCHAR(255) NOT NULL,
                product_image LONGBLOB,
                quantity INT NOT NULL DEFAULT 1,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(product_id) ON DELETE CASCADE
            )
        `;
        await promisePool.execute(createTableQuery);
    } catch (error) {
        console.error('❌ Error creating cart table:', error);
    }
};

// Create password_reset_otps table if it doesn't exist
const createPasswordResetOtpsTable = async () => {
    try {
        const createTableQuery = `
            CREATE TABLE IF NOT EXISTS password_reset_otps (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                otp VARCHAR(6) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email (email),
                INDEX idx_expires_at (expires_at)
            )
        `;
        await promisePool.execute(createTableQuery);
    } catch (error) {
        console.error('❌ Error creating password_reset_otps table:', error);
    }
};

// Update existing tables to match current schema
const updateDatabaseSchema = async () => {
    try {
        console.log('🔧 Checking database schema for updates...');
        
        // Check if updated_at column exists in users table, if not add it
        const [columns] = await promisePool.execute(
            "SHOW COLUMNS FROM users LIKE 'updated_at'"
        );
        
        if (columns.length === 0) {
            console.log('🔧 Adding updated_at column to users table...');
            await promisePool.execute(
                'ALTER TABLE users ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'
            );
            console.log('✅ Added updated_at column to users table');
        } else {
            console.log('✅ Database schema is up to date');
        }
    } catch (error) {
        console.error('❌ Error updating database schema:', error);
        console.log('💡 This is not critical - the application will continue to work');
        // Don't throw error, just log it as this is not critical
    }
};

// Initialize database
const initializeDatabase = async () => {
    await createUsersTable();
    await createProductsTable();
    await createSoldItemsTable();
    await createCartTable();
    await createPasswordResetOtpsTable();
    
    // Update database schema for existing installations
    await updateDatabaseSchema();
};

// Start database initialization
initializeDatabase();

// Cleanup expired OTPs periodically (every hour)
const cleanupExpiredOtps = async () => {
    try {
        const [result] = await promisePool.execute(
            'DELETE FROM password_reset_otps WHERE expires_at < NOW()'
        );
        if (result.affectedRows > 0) {
            console.log(`🧹 Cleaned up ${result.affectedRows} expired OTPs`);
        }
    } catch (error) {
        console.error('❌ Error cleaning up expired OTPs:', error);
    }
};

// Run cleanup every hour (3600000 ms)
setInterval(cleanupExpiredOtps, 3600000);

// Run initial cleanup
cleanupExpiredOtps();

// Routes

// Home page - serve index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve static HTML pages
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/signin', (req, res) => {
    res.sendFile(path.join(__dirname, 'signin.html'));
});

app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/account', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'Account.html'));
});

app.get('/cart', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'cart.html'));
});

app.get('/contact', (req, res) => {
    res.sendFile(path.join(__dirname, 'contact_us.html'));
});

// Test email page (for development)
app.get('/test-email', (req, res) => {
    res.sendFile(path.join(__dirname, 'test-email.html'));
});

// Forgot password page
app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'forgot-password.html'));
});

// Forgot password demo page
app.get('/forgot-password-demo', (req, res) => {
    res.sendFile(path.join(__dirname, 'forgot-password-demo.html'));
});

// API Routes

// User Registration (Sign Up)
app.post('/signin', async (req, res) => {
    try {
        const { username, emil: email, phone, password, location } = req.body;

        // Validate required fields
        if (!username || !email || !phone || !password || !location) {
            return res.status(400).send(`
                <script>
                    alert('All fields are required');
                    window.history.back();
                </script>
            `);
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).send(`
                <script>
                    alert('Please enter a valid email address');
                    window.history.back();
                </script>
            `);
        }

        // Validate phone number (basic validation)
        const phoneRegex = /^[\+]?[\d\s\-\(\)]{10,}$/;
        if (!phoneRegex.test(phone)) {
            return res.status(400).send(`
                <script>
                    alert('Please enter a valid phone number');
                    window.history.back();
                </script>
            `);
        }

        // Check if user already exists
        const [existingUsers] = await promisePool.execute(
            'SELECT id FROM users WHERE email = ? OR username = ?',
            [email, username]
        );

        if (existingUsers.length > 0) {
            return res.status(409).send(`
                <script>
                    alert('User with this email or username already exists');
                    window.history.back();
                </script>
            `);
        }

        // Hash password
        const saltRounds = config.security.bcryptSaltRounds;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Insert new user
        const [result] = await promisePool.execute(
            'INSERT INTO users (username, email, phone, password_hash, location) VALUES (?, ?, ?, ?, ?)',
            [username, email, phone, passwordHash, location]
        );

        console.log(`✅ New user registered: ${username} (ID: ${result.insertId})`);

        // Send welcome email (don't block registration if email fails)
        sendWelcomeEmail(email, username).then((emailResult) => {
            if (emailResult.success) {
                console.log(`📧 Welcome email sent to: ${email}`);
            } else {
                console.warn(`⚠️  Welcome email failed for: ${email} - ${emailResult.error}`);
            }
        }).catch((emailError) => {
            console.error(`❌ Welcome email error for: ${email}`, emailError);
        });

        // Successful registration - redirect to login page with success message
        res.send(`
            <script>
                alert('Account created successfully! Please login to continue.');
                window.location.href = '/login';
            </script>
        `);

    } catch (error) {
        console.error('❌ Registration error:', error);
        res.status(500).send(`
            <script>
                alert('Server error. Please try again later.');
                window.history.back();
            </script>
        `);
    }
});

// User Login
app.post('/login', async (req, res) => {
    try {
        // Handle the field name 'emil' from the login form (typo in HTML)
        const email = req.body.emil || req.body.email || req.body.username;
        const password = req.body.password;

        console.log('Login attempt with:', { email, password: password ? '***' : 'missing' });
        console.log('Request body:', req.body);

        // Validate required fields
        if (!email || !password) {
            return res.status(400).send(`
                <script>
                    alert('Email and password are required');
                    window.history.back();
                </script>
            `);
        }

        // Find user by email
        const [users] = await promisePool.execute(
            'SELECT id, username, email, password_hash FROM users WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(401).send(`
                <script>
                    alert('Invalid email or password');
                    window.history.back();
                </script>
            `);
        }

        const user = users[0];

        // Verify password
        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        if (!passwordMatch) {
            return res.status(401).send(`
                <script>
                    alert('Invalid email or password');
                    window.history.back();
                </script>
            `);
        }

        // Create session
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.email = user.email;

        console.log(`✅ User logged in: ${user.username} (ID: ${user.id})`);

        // Successful login - redirect to dashboard
        res.redirect('/dashboard');

    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).send(`
            <script>
                alert('Server error. Please try again later.');
                window.history.back();
            </script>
        `);
    }
});

// Get user profile
app.get('/api/profile', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({
                success: false,
                message: 'Not authenticated'
            });
        }

        const [users] = await promisePool.execute(
            'SELECT id, username, email, phone, location, created_at FROM users WHERE id = ?',
            [req.session.userId]
        );

        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            user: users[0]
        });

    } catch (error) {
        console.error('❌ Profile fetch error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Update user profile
app.put('/api/profile', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({
                success: false,
                message: 'Not authenticated'
            });
        }

        const { username, phone, location } = req.body;

        // Validate required fields
        if (!username || !phone || !location) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        // Check if username is already taken by another user
        const [existingUsers] = await promisePool.execute(
            'SELECT id FROM users WHERE username = ? AND id != ?',
            [username, req.session.userId]
        );

        if (existingUsers.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'Username is already taken'
            });
        }

        // Update user profile
        await promisePool.execute(
            'UPDATE users SET username = ?, phone = ?, location = ? WHERE id = ?',
            [username, phone, location, req.session.userId]
        );

        // Update session
        req.session.username = username;

        console.log(`✅ Profile updated for user ID: ${req.session.userId}`);

        res.json({
            success: true,
            message: 'Profile updated successfully!'
        });

    } catch (error) {
        console.error('❌ Profile update error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Logout
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('❌ Logout error:', err);
            return res.status(500).json({
                success: false,
                message: 'Error logging out'
            });
        }

        res.json({
            success: true,
            message: 'Logged out successfully',
            redirectUrl: '/'
        });
    });
});

// Check authentication status
app.get('/api/auth-status', (req, res) => {
    res.json({
        authenticated: !!req.session.userId,
        user: req.session.userId ? {
            id: req.session.userId,
            username: req.session.username,
            email: req.session.email
        } : null
    });
});

// =============================================================
// FORGOT PASSWORD API ENDPOINTS
// =============================================================

// Generate and send OTP for password reset
app.post('/api/forgot-password/send-otp', async (req, res) => {
    try {
        const { email } = req.body;

        // Validate email
        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: 'Please enter a valid email address'
            });
        }

        // Check if user exists
        const [users] = await promisePool.execute(
            'SELECT id, username FROM users WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'No account found with this email address'
            });
        }

        const user = users[0];

        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Set expiration time (10 minutes from now)
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

        // Delete any existing OTPs for this email
        await promisePool.execute(
            'DELETE FROM password_reset_otps WHERE email = ?',
            [email]
        );

        // Store OTP in database
        await promisePool.execute(
            'INSERT INTO password_reset_otps (email, otp, expires_at) VALUES (?, ?, ?)',
            [email, otp, expiresAt]
        );

        // Send OTP email
        const emailResult = await sendPasswordResetOTP(email, user.username, otp);

        if (emailResult.success) {
            console.log(`✅ Password reset OTP sent to: ${email}`);
            res.json({
                success: true,
                message: 'OTP sent successfully! Please check your email.'
            });
        } else {
            console.error(`❌ Failed to send OTP to: ${email}`);
            res.status(500).json({
                success: false,
                message: 'Failed to send OTP. Please try again.'
            });
        }

    } catch (error) {
        console.error('❌ Send OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error. Please try again later.'
        });
    }
});

// Verify OTP for password reset
app.post('/api/forgot-password/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;

        // Validate input
        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Email and OTP are required'
            });
        }

        if (otp.length !== 6) {
            return res.status(400).json({
                success: false,
                message: 'OTP must be 6 digits'
            });
        }

        // Check if OTP exists and is valid
        const [otpRecords] = await promisePool.execute(
            'SELECT * FROM password_reset_otps WHERE email = ? AND otp = ? AND used = FALSE AND expires_at > NOW()',
            [email, otp]
        );

        if (otpRecords.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired OTP'
            });
        }

        // Mark OTP as used
        await promisePool.execute(
            'UPDATE password_reset_otps SET used = TRUE WHERE email = ? AND otp = ?',
            [email, otp]
        );

        console.log(`✅ OTP verified for: ${email}`);

        res.json({
            success: true,
            message: 'OTP verified successfully'
        });

    } catch (error) {
        console.error('❌ Verify OTP error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error. Please try again later.'
        });
    }
});

// Reset password after OTP verification
app.post('/api/forgot-password/reset-password', async (req, res) => {
    try {
        const { email, newPassword } = req.body;

        // Validate input
        if (!email || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Email and new password are required'
            });
        }

        // Validate password strength
        if (newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long'
            });
        }

        const hasUpper = /[A-Z]/.test(newPassword);
        const hasLower = /[a-z]/.test(newPassword);
        const hasNumber = /\d/.test(newPassword);

        if (!hasUpper || !hasLower || !hasNumber) {
            return res.status(400).json({
                success: false,
                message: 'Password must contain at least one uppercase letter, one lowercase letter, and one number'
            });
        }

        // Check if there's a recent verified OTP for this email
        const [recentOtps] = await promisePool.execute(
            'SELECT * FROM password_reset_otps WHERE email = ? AND used = TRUE AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE) ORDER BY created_at DESC LIMIT 1',
            [email]
        );

        if (recentOtps.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No valid password reset session found. Please start the process again.'
            });
        }

        // Check if user exists
        const [users] = await promisePool.execute(
            'SELECT id FROM users WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Hash the new password
        const saltRounds = config.security.bcryptSaltRounds;
        const passwordHash = await bcrypt.hash(newPassword, saltRounds);

        // Update user's password
        await promisePool.execute(
            'UPDATE users SET password_hash = ? WHERE email = ?',
            [passwordHash, email]
        );

        // Clean up: delete all OTPs for this email
        await promisePool.execute(
            'DELETE FROM password_reset_otps WHERE email = ?',
            [email]
        );

        console.log(`✅ Password reset successfully for: ${email}`);

        res.json({
            success: true,
            message: 'Password reset successfully! You can now login with your new password.'
        });

    } catch (error) {
        console.error('❌ Reset password error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error. Please try again later.'
        });
    }
});

// =============================================================
// PRODUCT API ENDPOINTS
// =============================================================

// Add new product with Cloudinary support
app.post('/api/add-product', upload.array('images', 3), async (req, res) => {
    console.log('\n🔄 === NEW PRODUCT UPLOAD REQUEST ===');
    console.log('📊 Request details:');
    console.log('   - User ID:', req.session.userId || 'Not logged in');
    console.log('   - Content-Type:', req.headers['content-type']);
    console.log('   - Files received:', req.files ? req.files.length : 0);
    console.log('   - Files object:', req.files);
    console.log('   - Form data:', req.body);
    
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in to add products' });
    }

    const { name, description, price, category, condition } = req.body;
    const userId = req.session.userId;

    // Validate required fields
    if (!name || !category || !condition) {
        return res.status(400).json({ 
            success: false, 
            message: 'Name, category, and condition are required' 
        });
    }

    // Validate price (if provided)
    let finalPrice = 0;
    if (price && price !== '') {
        if (isNaN(price) || parseFloat(price) < 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Please enter a valid price' 
            });
        }
        finalPrice = parseFloat(price);
    }

    try {
        // Upload images to Cloudinary
        const imageUrls = { image1_url: null, image2_url: null, image3_url: null };
        
        console.log(`📤 Processing product "${name}" from user ${userId}`);
        console.log(`📷 Received ${req.files ? req.files.length : 0} image files`);
        
        if (req.files && req.files.length > 0) {
            for (let i = 0; i < Math.min(req.files.length, 3); i++) {
                const file = req.files[i];
                
                try {
                    console.log(`📤 Uploading image ${i + 1}: ${file.originalname} (${file.size} bytes)`);
                    
                    // Convert buffer to base64 for Cloudinary upload
                    const base64Data = `data:${file.mimetype};base64,${file.buffer.toString('base64')}`;
                    
                    const uploadOptions = {
                        folder: 'educycle/products',
                        public_id: `product_${userId}_${Date.now()}_${i + 1}`,
                        resource_type: 'image',
                        quality: 'auto:good',
                        format: 'webp',
                        transformation: [
                            { width: 800, height: 600, crop: 'limit', quality: 'auto:good' }
                        ]
                    };
                    
                    const result = await cloudinary.uploader.upload(base64Data, uploadOptions);
                    imageUrls[`image${i + 1}_url`] = result.secure_url;
                    
                    console.log(`✅ Image ${i + 1} uploaded to Cloudinary: ${result.secure_url}`);
                    
                } catch (uploadError) {
                    console.error(`❌ Failed to upload image ${i + 1}:`, uploadError);
                    // Continue with other images even if one fails
                }
            }
        } else {
            console.log('ℹ️  No image files received');
        }

        // Insert product with Cloudinary URLs
        const [result] = await promisePool.execute(
            'INSERT INTO products (user_id, name, description, price, category, condition_item, image1_url, image2_url, image3_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [userId, name, description || '', finalPrice, category, condition, imageUrls.image1_url, imageUrls.image2_url, imageUrls.image3_url]
        );

        console.log(`✅ Product "${name}" added successfully (ID: ${result.insertId})`);

        // Get user email and username for notification
        const [userData] = await promisePool.execute(
            'SELECT email, username FROM users WHERE id = ?',
            [userId]
        );

        if (userData.length > 0) {
            // Send product listing notification email (don't block response if email fails)
            sendProductListingNotification(userData[0].email, userData[0].username, name).then((emailResult) => {
                if (emailResult.success) {
                    console.log(`📧 Product listing notification sent to: ${userData[0].email}`);
                } else {
                    console.warn(`⚠️  Product listing notification failed for: ${userData[0].email} - ${emailResult.error}`);
                }
            }).catch((emailError) => {
                console.error(`❌ Product listing notification error for: ${userData[0].email}`, emailError);
            });
        }

        res.json({
            success: true,
            message: 'Product added successfully!',
            productId: result.insertId,
            images: imageUrls
        });

    } catch (error) {
        console.error('❌ Add product error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add product. Please try again.'
        });
    }
});

// Add product with direct Cloudinary URLs (for client-side uploads)
app.post('/api/add-product-direct', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in to add products' });
    }

    try {
        console.log('🔄 === NEW DIRECT PRODUCT UPLOAD REQUEST ===');
        console.log('📊 Request details:');
        console.log('   - User ID:', req.session.userId);
        console.log('   - Body:', req.body);

        const { name, description, category, condition, price, imageUrls } = req.body;

        // Validate required fields
        if (!name || !description || !category) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }

        // Validate image URLs (should be Cloudinary URLs)
        const validatedImageUrls = {};
        if (imageUrls) {
            if (imageUrls.image1 && imageUrls.image1.includes('cloudinary.com')) {
                validatedImageUrls.image1 = imageUrls.image1;
            }
            if (imageUrls.image2 && imageUrls.image2.includes('cloudinary.com')) {
                validatedImageUrls.image2 = imageUrls.image2;
            }
            if (imageUrls.image3 && imageUrls.image3.includes('cloudinary.com')) {
                validatedImageUrls.image3 = imageUrls.image3;
            }
        }

        console.log('📷 Validated Cloudinary URLs:', validatedImageUrls);

        let result;
        
        // Check if this is a software product
        if (category === 'software') {
            console.log('💻 Processing as SOFTWARE product');
            
            // Extract software-specific fields
            const {
                tagline,
                platform,
                version,
                techStack,
                developerName,
                licenseType,
                downloadLink,
                demoLink,
                githubLink,
                documentationLink,
                features,
                systemRequirements,
                categoryId,
                contactSupport
            } = req.body;

            // Validate required software fields
            if (!platform || !developerName || !categoryId) {
                return res.status(400).json({
                    success: false,
                    message: 'Missing required software fields (platform, developer name, category)'
                });
            }

            // Insert into software_products table
            const [softwareResult] = await promisePool.execute(`
                INSERT INTO software_products (
                    user_id, name, description, tagline, price,
                    image1_url, image2_url, image3_url,
                    platform, tech_stack, developer_name, license_type, version,
                    download_link, demo_link, github_link, documentation_link,
                    features, system_requirements,
                    is_active, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NOW())
            `, [
                req.session.userId,
                name,
                description,
                tagline || null,
                parseFloat(price) || 0,
                validatedImageUrls.image1 || null,
                validatedImageUrls.image2 || null,
                validatedImageUrls.image3 || null,
                platform,
                techStack || null,
                developerName,
                licenseType || 'Proprietary',
                version || '1.0.0',
                downloadLink || null,
                demoLink || null,
                githubLink || null,
                documentationLink || null,
                features || null,
                systemRequirements || null
            ]);

            const softwareId = softwareResult.insertId;

            // Add software to category junction table
            if (categoryId) {
                try {
                    await promisePool.execute(`
                        INSERT INTO software_product_categories (software_id, category_id)
                        VALUES (?, ?)
                    `, [softwareId, parseInt(categoryId)]);
                } catch (categoryError) {
                    console.log('⚠️ Warning: Failed to add software category relationship:', categoryError.message);
                }
            }

            result = softwareResult;
            console.log('✅ Software product added successfully:', {
                softwareId: result.insertId,
                platform,
                developerName,
                categoryId,
                imageUrls: validatedImageUrls
            });

        } else {
            console.log('📦 Processing as REGULAR product');
            
            // Validate condition for regular products
            if (!condition) {
                return res.status(400).json({
                    success: false,
                    message: 'Condition is required for regular products'
                });
            }

            // Insert into regular products table
            const [regularResult] = await promisePool.execute(`
                INSERT INTO products (
                    user_id, name, description, category, condition_item, price,
                    image1_url, image2_url, image3_url,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
            `, [
                req.session.userId,
                name,
                description,
                category,
                condition,
                parseFloat(price) || 0,
                validatedImageUrls.image1 || null,
                validatedImageUrls.image2 || null,
                validatedImageUrls.image3 || null
            ]);

            result = regularResult;
            console.log('✅ Regular product added successfully:', {
                productId: result.insertId,
                category,
                condition,
                imageUrls: validatedImageUrls
            });
        }

        // Send email notification (optional)
        const [userData] = await promisePool.execute('SELECT email FROM users WHERE id = ?', [req.session.userId]);
        if (userData.length > 0) {
            const productType = category === 'software' ? 'software' : 'product';
            sendProductListingNotification(userData[0].email, name, category).then((emailResult) => {
                if (emailResult.success) {
                    console.log(`📧 ${productType} listing notification sent to:`, userData[0].email);
                } else {
                    console.warn(`⚠️  ${productType} listing notification failed for: ${userData[0].email} - ${emailResult.error}`);
                }
            }).catch((emailError) => {
                console.error(`❌ ${productType} listing notification error for: ${userData[0].email}`, emailError);
            });
        }

        res.json({
            success: true,
            message: `${category === 'software' ? 'Software' : 'Product'} added successfully with direct upload!`,
            productId: result.insertId,
            productType: category === 'software' ? 'software' : 'regular',
            images: validatedImageUrls
        });

    } catch (error) {
        console.error('❌ Add product direct error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add product. Please try again.'
        });
    }
});

// Get frontend configuration (Cloudinary settings for direct upload)
app.get('/api/config', (req, res) => {
    res.json({
        success: true,
        cloudinary: {
            cloudName: config.cloudinary.cloudName,
            uploadPreset: config.cloudinary.uploadPreset
        }
    });
});

// Get all products (for browsing)
app.get('/api/products', async (req, res) => {
    try {
        const { category, search } = req.query;
        let query = `
            SELECT 
                p.product_id,
                p.name,
                p.description,
                p.price,
                p.category,
                p.condition_item,
                p.image1_url,
                p.image2_url,
                p.image3_url,
                p.image1,
                p.image2,
                p.image3,
                p.created_at,
                u.username as seller_name,
                u.location as seller_location,
                u.phone as seller_phone
            FROM products p
            JOIN users u ON p.user_id = u.id
            WHERE 1=1
        `;
        const params = [];

        // Exclude current user's products if logged in
        if (req.session.userId) {
            query += ' AND p.user_id != ?';
            params.push(req.session.userId);
        }

        // Filter by category
        if (category && category !== 'all') {
            query += ' AND p.category LIKE ?';
            params.push(`%${category}%`);
        }

        // Search filter
        if (search) {
            query += ' AND (p.name LIKE ? OR p.description LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
        }

        query += ' ORDER BY p.created_at DESC';

        const [products] = await promisePool.execute(query, params);

        // Return images from Cloudinary URLs or fallback to base64 for backward compatibility
        const productsWithImages = products.map(product => ({
            ...product,
            image1: product.image1_url || (product.image1 ? `data:image/jpeg;base64,${product.image1.toString('base64')}` : null),
            image2: product.image2_url || (product.image2 ? `data:image/jpeg;base64,${product.image2.toString('base64')}` : null),
            image3: product.image3_url || (product.image3 ? `data:image/jpeg;base64,${product.image3.toString('base64')}` : null),
            // Remove URL fields from response for cleaner API
            image1_url: undefined,
            image2_url: undefined,
            image3_url: undefined
        }));

        res.json({
            success: true,
            products: productsWithImages,
            count: productsWithImages.length
        });

    } catch (error) {
        console.error('❌ Get products error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch products'
        });
    }
});

// Get all products (both regular and software) for home page
app.get('/api/all-products', async (req, res) => {
    try {
        const { category, search } = req.query;
        
        // Fetch regular products
        let regularQuery = `
            SELECT 
                p.product_id,
                p.name,
                p.description,
                p.price,
                p.category,
                p.condition_item,
                p.image1_url,
                p.image2_url,
                p.image3_url,
                p.image1,
                p.image2,
                p.image3,
                p.created_at,
                u.username as seller_name,
                u.location as seller_location,
                u.phone as seller_phone,
                'regular' as product_type
            FROM products p
            JOIN users u ON p.user_id = u.id
            WHERE 1=1
        `;
        const regularParams = [];

        // Exclude current user's products if logged in
        if (req.session.userId) {
            regularQuery += ' AND p.user_id != ?';
            regularParams.push(req.session.userId);
        }

        // Filter by category for regular products
        if (category && category !== 'all' && category !== 'software') {
            regularQuery += ' AND p.category LIKE ?';
            regularParams.push(`%${category}%`);
        }

        // Search filter for regular products
        if (search) {
            regularQuery += ' AND (p.name LIKE ? OR p.description LIKE ?)';
            regularParams.push(`%${search}%`, `%${search}%`);
        }

        regularQuery += ' ORDER BY p.created_at DESC';

        const [regularProducts] = await promisePool.execute(regularQuery, regularParams);

        // Process regular products images
        const regularProductsWithImages = regularProducts.map(product => ({
            ...product,
            image1: product.image1_url || (product.image1 ? `data:image/jpeg;base64,${product.image1.toString('base64')}` : null),
            image2: product.image2_url || (product.image2 ? `data:image/jpeg;base64,${product.image2.toString('base64')}` : null),
            image3: product.image3_url || (product.image3 ? `data:image/jpeg;base64,${product.image3.toString('base64')}` : null),
            image1_url: undefined,
            image2_url: undefined,
            image3_url: undefined
        }));

        // Fetch software products
        let softwareQuery = `
            SELECT 
                sp.software_id as product_id,
                sp.name,
                sp.description,
                sp.price,
                sp.image1_url,
                sp.image2_url,
                sp.image3_url,
                sp.platform,
                sp.tech_stack,
                sp.developer_name,
                sp.created_at,
                u.username as seller_name,
                u.location as seller_location,
                NULL as seller_phone,
                'software' as product_type,
                'software' as category,
                'New' as condition_item
            FROM software_products sp
            JOIN users u ON sp.user_id = u.id
            WHERE sp.is_active = true
        `;
        const softwareParams = [];

        // Exclude current user's software if logged in
        if (req.session.userId) {
            softwareQuery += ' AND sp.user_id != ?';
            softwareParams.push(req.session.userId);
        }

        // Filter by category for software products (only include if category is 'software' or 'all')
        if (category && category !== 'all' && category === 'software') {
            // Include all software products when category is 'software'
        } else if (category && category !== 'all' && category !== 'software') {
            // Exclude software products if a specific non-software category is selected
            softwareQuery += ' AND 1=0'; // This will exclude all software products
        }

        // Search filter for software products
        if (search) {
            softwareQuery += ' AND (sp.name LIKE ? OR sp.description LIKE ? OR sp.tech_stack LIKE ?)';
            softwareParams.push(`%${search}%`, `%${search}%`, `%${search}%`);
        }

        softwareQuery += ' ORDER BY sp.created_at DESC';

        const [softwareProducts] = await promisePool.execute(softwareQuery, softwareParams);

        // Process software products images
        const softwareProductsWithImages = softwareProducts.map(product => ({
            ...product,
            image1: product.image1_url,
            image2: product.image2_url,
            image3: product.image3_url,
            image1_url: undefined,
            image2_url: undefined,
            image3_url: undefined
        }));

        // Combine all products
        const allProducts = [...regularProductsWithImages, ...softwareProductsWithImages];
        
        // Sort combined products by creation date (newest first)
        allProducts.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        res.json({
            success: true,
            products: allProducts,
            count: allProducts.length,
            breakdown: {
                regular: regularProductsWithImages.length,
                software: softwareProductsWithImages.length
            }
        });

    } catch (error) {
        console.error('❌ Get all products error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch products'
        });
    }
});

// Search API endpoint for both products and software
app.get('/api/search', async (req, res) => {
    try {
        const { category, search } = req.query;
        let allResults = [];
        // Validate and sanitize limit
        let limit = 10;
        if (req.query.limit) {
            const parsedLimit = parseInt(req.query.limit);
            if (!isNaN(parsedLimit) && parsedLimit > 0 && parsedLimit <= 100) {
                limit = parsedLimit;
            }
        }

        // --- REGULAR PRODUCTS SEARCH ---
        if (!category || category !== 'software') {
            let regularQuery = `
                SELECT 
                    p.product_id,
                    p.name,
                    p.description,
                    p.price,
                    p.category,
                    p.condition_item,
                    p.image1_url,
                    p.image2_url,
                    p.image3_url,
                    p.image1,
                    p.image2,
                    p.image3,
                    p.created_at,
                    u.username as seller_name,
                    u.location as seller_location,
                    u.phone as seller_phone,
                    'regular' as product_type
                FROM products p
                JOIN users u ON p.user_id = u.id
                WHERE 1=1
            `;
            const regularParams = [];

            // Exclude current user's products if logged in
            if (req.session && req.session.userId) {
                regularQuery += ' AND p.user_id != ?';
                regularParams.push(req.session.userId);
            }

            // Category filter for regular products
            let hasCategory = false;
            if (category && category !== 'all' && category !== 'software') {
                regularQuery += ' AND INSTR(LOWER(p.category), ?) > 0';
                regularParams.push(category.toLowerCase());
                hasCategory = true;
            }

            // Search filter for regular products (case-insensitive, only if 3+ chars)
            let hasSearch = false;
            if (search && search.trim().length >= 3) {
                regularQuery += ' AND (LOWER(p.name) LIKE ? OR LOWER(p.description) LIKE ? OR LOWER(p.category) LIKE ?)';
                const s = `%${search.toLowerCase()}%`;
                regularParams.push(s, s, s);
                hasSearch = true;
            }

            regularQuery += ` ORDER BY p.created_at DESC LIMIT ${limit}`;

            // Debug: print query and params
            console.log('🔍 Regular query:', regularQuery);
            console.log('🔍 Regular params:', regularParams);

            // Only execute if params match placeholders
            const [regularProducts] = await promisePool.execute(regularQuery, regularParams);

            // Process regular products
            const processedRegularProducts = regularProducts.map(product => ({
                ...product,
                image1: product.image1_url || (product.image1 ? `data:image/jpeg;base64,${product.image1.toString('base64')}` : null),
                image2: product.image2_url || (product.image2 ? `data:image/jpeg;base64,${product.image2.toString('base64')}` : null),
                image3: product.image3_url || (product.image3 ? `data:image/jpeg;base64,${product.image3.toString('base64')}` : null),
                image1_url: product.image1_url,
                image2_url: undefined,
                image3_url: undefined
            }));

            allResults = [...allResults, ...processedRegularProducts];
        }

        // Search software products only if category is 'software' or 'all' or not specified
        if (!category || category === 'all' || category === 'software') {
            let softwareQuery = `
                SELECT 
                    sp.software_id,
                    sp.name,
                    sp.description,
                    sp.tagline,
                    sp.price,
                    sp.image1_url,
                    sp.image2_url,
                    sp.image3_url,
                    sp.platform,
                    sp.tech_stack,
                    sp.developer_name,
                    sp.created_at,
                    u.username as seller_name,
                    u.location as seller_location,
                    NULL as seller_phone,
                    'software' as product_type,
                    'software' as category,
                    'New' as condition_item
                FROM software_products sp
                JOIN users u ON sp.user_id = u.id
                WHERE sp.is_active = true
            `;
            const softwareParams = [];

            // Exclude current user's software if logged in
            if (req.session.userId) {
                softwareQuery += ' AND sp.user_id != ?';
                softwareParams.push(req.session.userId);
            }

            // Search filter for software products (case-insensitive)
            if (search) {
                softwareQuery += ' AND (LOWER(sp.name) LIKE ? OR LOWER(sp.description) LIKE ? OR LOWER(sp.tagline) LIKE ? OR LOWER(sp.tech_stack) LIKE ? OR LOWER(sp.developer_name) LIKE ?)';
                softwareParams.push(`%${search.toLowerCase()}%`, `%${search.toLowerCase()}%`, `%${search.toLowerCase()}%`, `%${search.toLowerCase()}%`, `%${search.toLowerCase()}%`);
            }

            softwareQuery += ` ORDER BY sp.created_at DESC LIMIT ${limit}`;

            console.log('🔍 Software query:', softwareQuery);
            console.log('🔍 Software params:', softwareParams);

            const [softwareProducts] = await promisePool.execute(softwareQuery, softwareParams);

            // Process software products
            const processedSoftwareProducts = softwareProducts.map(product => ({
                ...product,
                image1: product.image1_url,
                image2: product.image2_url,
                image3: product.image3_url,
                image1_url: product.image1_url,
                image2_url: undefined,
                image3_url: undefined
            }));

            allResults = [...allResults, ...processedSoftwareProducts];
        }

        // Sort combined results by relevance and date
        allResults.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        // Limit final results
        const finalResults = allResults.slice(0, parseInt(limit));

        res.json({
            success: true,
            products: finalResults,
            count: finalResults.length,
            breakdown: {
                regular: finalResults.filter(p => p.product_type === 'regular').length,
                software: finalResults.filter(p => p.product_type === 'software').length
            }
        });

    } catch (error) {
        console.error('❌ Search error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to perform search'
        });
    }
});

// Get user's own products
app.get('/api/my-products', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    try {
        console.log('🔍 Fetching products for user ID:', req.session.userId);
        
        // Fetch regular products
        const [products] = await promisePool.execute(`
            SELECT 
                product_id,
                name,
                description,
                price,
                category,
                condition_item,
                image1_url,
                image2_url,
                image3_url,
                image1,
                image2,
                image3,
                created_at,
                'regular' as product_type
            FROM products 
            WHERE user_id = ?
            ORDER BY created_at DESC
        `, [req.session.userId]);

        console.log('📦 Regular products found:', products.length);

        // Fetch software products
        const [softwareProducts] = await promisePool.execute(`
            SELECT 
                software_id as product_id,
                name,
                description,
                price,
                tech_stack,
                platform,
                version,
                image1_url,
                image2_url,
                image3_url,
                created_at,
                'software' as product_type
            FROM software_products 
            WHERE user_id = ?
            ORDER BY created_at DESC
        `, [req.session.userId]);

        console.log('💻 Software products found:', softwareProducts.length);

        // Process regular products
        const processedProducts = products.map(product => ({
            ...product,
            image1: product.image1_url || (product.image1 ? `data:image/jpeg;base64,${product.image1.toString('base64')}` : null),
            image2: product.image2_url || (product.image2 ? `data:image/jpeg;base64,${product.image2.toString('base64')}` : null),
            image3: product.image3_url || (product.image3 ? `data:image/jpeg;base64,${product.image3.toString('base64')}` : null),
            image1_url: undefined,
            image2_url: undefined,
            image3_url: undefined
        }));

        // Process software products
        const processedSoftwareProducts = softwareProducts.map(software => ({
            ...software,
            image1: software.image1_url || null,
            image2: software.image2_url || null,
            image3: software.image3_url || null,
            image1_url: undefined,
            image2_url: undefined,
            image3_url: undefined
        }));

        // Combine both product types and sort by created_at
        const allProducts = [...processedProducts, ...processedSoftwareProducts]
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        console.log('✅ Total products combined:', allProducts.length);

        res.json({
            success: true,
            products: allProducts,
            count: allProducts.length
        });

    } catch (error) {
        console.error('❌ Get my products error:', error);
        console.error('Error details:', error.message);
        console.error('Error stack:', error.stack);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch your products',
            error: error.message
        });
    }
});

// ==================== SOFTWARE PRODUCTS API ENDPOINTS ====================

// Get all software products
app.get('/api/software', async (req, res) => {
    try {
        const { category, search, sort = 'created_at', order = 'DESC' } = req.query;
        
        // Use the appropriate database connection
        const dbConnection = promisePool || db;
        const executeQuery = promisePool ? 
            (query, params) => promisePool.execute(query, params) :
            (query, params) => db.query(query, params);
        
        let query = `
            SELECT 
                sp.software_id,
                sp.name,
                sp.description,
                sp.tagline,
                sp.price,
                sp.image1_url,
                sp.image2_url,
                sp.image3_url,
                sp.platform,
                sp.tech_stack,
                sp.developer_name,
                sp.license_type,
                sp.version,
                sp.downloads_count,
                sp.views_count,
                sp.created_at,
                u.username as seller_name,
                u.location as seller_location,
                AVG(sr.rating) as avg_rating,
                COUNT(sr.review_id) as review_count
            FROM software_products sp
            JOIN users u ON sp.user_id = u.id
            LEFT JOIN software_reviews sr ON sp.software_id = sr.software_id
            WHERE sp.is_active = true
        `;
        const params = [];

        // Exclude current user's products if logged in
        if (req.session.userId) {
            query += ' AND sp.user_id != ?';
            params.push(req.session.userId);
        }

        // Category filter
        if (category && category !== 'all') {
            query += ` AND EXISTS (
                SELECT 1 FROM software_product_categories spc 
                JOIN software_categories sc ON spc.category_id = sc.category_id 
                WHERE spc.software_id = sp.software_id AND sc.name = ?
            )`;
            params.push(category);
        }

        // Search filter
        if (search) {
            query += ' AND (sp.name ILIKE ? OR sp.description ILIKE ? OR sp.tech_stack ILIKE ?)';
            params.push(`%${search}%`, `%${search}%`, `%${search}%`);
        }

        query += ` GROUP BY sp.software_id, u.username, u.location`;
        query += ` ORDER BY sp.${sort} ${order}`;

        const [software] = await executeQuery(query, params);

        res.json({
            success: true,
            software: software,
            count: software.length
        });

    } catch (error) {
        console.error('❌ Get software error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch software products'
        });
    }
});

// Get software product for editing (no view count increment)
app.get('/api/software/:id/edit', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    try {
        const softwareId = req.params.id;
        
        // Get software details with user verification
        const [software] = await promisePool.execute(`
            SELECT 
                sp.*,
                u.username as seller_name
            FROM software_products sp
            JOIN users u ON sp.user_id = u.id
            WHERE sp.software_id = ? AND sp.user_id = ? AND sp.is_active = true
        `, [softwareId, req.session.userId]);

        if (software.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Software not found or you do not have permission to edit it'
            });
        }

        const product = software[0];

        // Get software categories
        const [categories] = await promisePool.execute(`
            SELECT sc.name, sc.icon
            FROM software_categories spc
            JOIN categories sc ON spc.category_id = sc.id
            WHERE spc.software_id = ?
        `, [softwareId]);

        // Parse features and system requirements
        let features = [];
        let systemRequirements = {};

        if (product.features) {
            try {
                features = JSON.parse(product.features);
            } catch (e) {
                features = product.features.split(',').map(f => f.trim());
            }
        }

        if (product.system_requirements) {
            try {
                systemRequirements = JSON.parse(product.system_requirements);
            } catch (e) {
                systemRequirements = { general: product.system_requirements };
            }
        }

        // Prepare response for editing
        const softwareEdit = {
            software_id: product.software_id,
            name: product.name,
            description: product.description,
            tagline: product.tagline,
            price: parseFloat(product.price),
            image1_url: product.image1_url,
            image2_url: product.image2_url,
            image3_url: product.image3_url,
            platform: product.platform,
            tech_stack: product.tech_stack,
            developer_name: product.developer_name,
            license_type: product.license_type,
            version: product.version,
            download_link: product.download_link,
            demo_link: product.demo_link,
            github_link: product.github_link,
            documentation_link: product.documentation_link,
            features: features,
            system_requirements: systemRequirements,
            categories: categories.map(cat => ({ name: cat.name, icon: cat.icon })),
            created_at: product.created_at
        };

        res.json({
            success: true,
            software: softwareEdit
        });

    } catch (error) {
        console.error('❌ Get software for edit error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get software details'
        });
    }
});

// Get single software product details
app.get('/api/software/:id', async (req, res) => {
    try {
        const softwareId = req.params.id;
        
        // Use the appropriate database connection
        const dbConnection = promisePool || db;
        const executeQuery = promisePool ? 
            (query, params) => promisePool.execute(query, params) :
            (query, params) => db.query(query, params);
        
        // Get software details
        const [software] = await executeQuery(`
            SELECT 
                sp.software_id,
                sp.name,
                sp.description,
                sp.tagline,
                sp.price,
                sp.image1_url,
                sp.image2_url,
                sp.image3_url,
                sp.platform,
                sp.tech_stack,
                sp.developer_name,
                sp.license_type,
                sp.version,
                sp.download_link,
                sp.demo_link,
                sp.github_link,
                sp.documentation_link,
                sp.features,
                sp.system_requirements,
                sp.downloads_count,
                sp.views_count,
                sp.created_at,
                u.id as seller_id,
                u.username as seller_name,
                u.email as seller_email,
                u.phone as seller_phone,
                u.location as seller_location,
                u.created_at as seller_member_since
            FROM software_products sp
            JOIN users u ON sp.user_id = u.id
            WHERE sp.software_id = ? AND sp.is_active = 1
        `, [softwareId]);

        if (software.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Software not found'
            });
        }

        const product = software[0];

        // Get software reviews and rating
        const [reviews] = await executeQuery(`
            SELECT 
                AVG(rating) as avg_rating,
                COUNT(*) as review_count
            FROM software_reviews 
            WHERE software_id = ?
        `, [softwareId]);

        // Get software categories
        const [categories] = await executeQuery(`
            SELECT sc.name, sc.icon
            FROM software_product_categories spc
            JOIN software_categories sc ON spc.category_id = sc.category_id
            WHERE spc.software_id = ?
        `, [softwareId]);

        // Get seller statistics
        const [sellerStats] = await executeQuery(`
            SELECT 
                COUNT(*) as total_software_count,
                SUM(downloads_count) as total_downloads
            FROM software_products 
            WHERE user_id = ? AND is_active = 1
        `, [product.seller_id]);

        // Increment view count
        await executeQuery(`
            UPDATE software_products 
            SET views_count = views_count + 1 
            WHERE software_id = ?
        `, [softwareId]);

        // Prepare images array
        const images = [];
        if (product.image1_url) images.push(product.image1_url);
        if (product.image2_url) images.push(product.image2_url);
        if (product.image3_url) images.push(product.image3_url);

        // Add default image if no images available
        if (images.length === 0) {
            images.push(`https://via.placeholder.com/500x500/232f3e/ffffff?text=${encodeURIComponent(product.name.substring(0, 20))}`);
        }

        // Parse features and system requirements
        let features = [];
        let systemRequirements = {};

        if (product.features) {
            try {
                features = JSON.parse(product.features);
            } catch (e) {
                features = product.features.split(',').map(f => f.trim());
            }
        }

        if (product.system_requirements) {
            try {
                systemRequirements = JSON.parse(product.system_requirements);
            } catch (e) {
                systemRequirements = { general: product.system_requirements };
            }
        }

        // Calculate member since year
        const memberSince = new Date(product.seller_member_since).getFullYear();

        // Prepare response
        const softwareDetail = {
            id: product.software_id,
            name: product.name,
            description: product.description,
            tagline: product.tagline,
            category: 'software',
            condition: 'New', // Software is always new
            price: parseFloat(product.price),
            isFree: parseFloat(product.price) === 0,
            images: images,
            created_at: product.created_at,
            
            // Software specific fields
            platform: product.platform,
            techStack: product.tech_stack,
            developerName: product.developer_name,
            licenseType: product.license_type,
            version: product.version,
            downloadLink: product.download_link,
            demoLink: product.demo_link,
            githubLink: product.github_link,
            documentationLink: product.documentation_link,
            features: features,
            systemRequirements: systemRequirements,
            
            // Statistics
            downloadsCount: product.downloads_count,
            viewsCount: product.views_count + 1, // Include current view
            avgRating: reviews[0]?.avg_rating || 0,
            reviewCount: reviews[0]?.review_count || 0,
            
            // Categories
            categories: categories.map(cat => ({ name: cat.name, icon: cat.icon })),
            
            // Seller information
            seller: {
                id: product.seller_id,
                name: product.seller_name,
                email: product.seller_email,
                phone: product.seller_phone,
                location: product.seller_location,
                avatar: product.seller_name.charAt(0).toUpperCase(),
                rating: reviews[0]?.avg_rating || 4.5,
                itemsSold: sellerStats[0]?.total_software_count || 0,
                totalDownloads: sellerStats[0]?.total_downloads || 0,
                memberSince: memberSince.toString()
            }
        };

        res.json({
            success: true,
            product: softwareDetail
        });

    } catch (error) {
        console.error('❌ Get software detail error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch software details'
        });
    }
});

// Get software categories
app.get('/api/software-categories', async (req, res) => {
    try {
        // Use the appropriate database connection
        const dbConnection = promisePool || db;
        const executeQuery = promisePool ? 
            (query, params) => promisePool.execute(query, params) :
            (query, params) => db.query(query, params);
        
        const [categories] = await executeQuery(`
            SELECT 
                category_id,
                name,
                description,
                icon,
                created_at
            FROM software_categories
            ORDER BY name ASC
        `);

        res.json({
            success: true,
            categories: categories
        });

    } catch (error) {
        console.error('❌ Get software categories error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch software categories'
        });
    }
});

// Add new software product
app.post('/api/software/add', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    try {
        const {
            name,
            description,
            tagline,
            price,
            image1_url,
            image2_url,
            image3_url,
            platform,
            tech_stack,
            developer_name,
            license_type,
            version,
            download_link,
            demo_link,
            github_link,
            documentation_link,
            features,
            system_requirements,
            categories
        } = req.body;

        // Use the appropriate database connection
        const dbConnection = promisePool || db;
        const executeQuery = promisePool ? 
            (query, params) => promisePool.execute(query, params) :
            (query, params) => db.query(query, params);

        // Insert software product
        const [result] = await executeQuery(`
            INSERT INTO software_products (
                user_id, name, description, tagline, price,
                image1_url, image2_url, image3_url,
                platform, tech_stack, developer_name, license_type, version,
                download_link, demo_link, github_link, documentation_link,
                features, system_requirements
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            req.session.userId, name, description, tagline, price || 0,
            image1_url, image2_url, image3_url,
            platform, tech_stack, developer_name, license_type, version || '1.0.0',
            download_link, demo_link, github_link, documentation_link,
            JSON.stringify(features || []), JSON.stringify(system_requirements || {})
        ]);

        const softwareId = result.insertId;

        // Add categories if provided
        if (categories && categories.length > 0) {
            for (const categoryName of categories) {
                // Get or create category
                let [category] = await executeQuery(`
                    SELECT category_id FROM software_categories WHERE name = ?
                `, [categoryName]);

                if (category.length === 0) {
                    const [newCategory] = await executeQuery(`
                        INSERT INTO software_categories (name) VALUES (?)
                    `, [categoryName]);
                    category = [{ category_id: newCategory.insertId }];
                }

                // Link software to category
                await executeQuery(`
                    INSERT INTO software_product_categories (software_id, category_id)
                    VALUES (?, ?) ON CONFLICT DO NOTHING
                `, [softwareId, category[0].category_id]);
            }
        }

        res.json({
            success: true,
            message: 'Software product added successfully',
            softwareId: softwareId
        });

    } catch (error) {
        console.error('❌ Add software error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add software product'
        });
    }
});

// Record software download
app.post('/api/software/:id/download', async (req, res) => {
    try {
        const softwareId = req.params.id;
        const userId = req.session.userId || null;
        const ipAddress = req.ip;
        const userAgent = req.get('User-Agent');

        // Use the appropriate database connection
        const dbConnection = promisePool || db;
        const executeQuery = promisePool ? 
            (query, params) => promisePool.execute(query, params) :
            (query, params) => db.query(query, params);

        // Record download
        await executeQuery(`
            INSERT INTO software_downloads (software_id, user_id, ip_address, user_agent)
            VALUES (?, ?, ?, ?)
        `, [softwareId, userId, ipAddress, userAgent]);

        // Increment download count
        await executeQuery(`
            UPDATE software_products 
            SET downloads_count = downloads_count + 1 
            WHERE software_id = ?
        `, [softwareId]);

        res.json({
            success: true,
            message: 'Download recorded'
        });

    } catch (error) {
        console.error('❌ Record download error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to record download'
        });
    }
});

// Get software categories
app.get('/api/software/categories', async (req, res) => {
    try {
        // Use the appropriate database connection
        const dbConnection = promisePool || db;
        const executeQuery = promisePool ? 
            (query, params) => promisePool.execute(query, params) :
            (query, params) => db.query(query, params);

        const [categories] = await executeQuery(`
            SELECT 
                sc.category_id,
                sc.name,
                sc.description,
                sc.icon,
                COUNT(spc.software_id) as software_count
            FROM software_categories sc
            LEFT JOIN software_product_categories spc ON sc.category_id = spc.category_id
            LEFT JOIN software_products sp ON spc.software_id = sp.software_id AND sp.is_active = true
            GROUP BY sc.category_id, sc.name, sc.description, sc.icon
            ORDER BY software_count DESC, sc.name
        `);

        res.json({
            success: true,
            categories: categories
        });

    } catch (error) {
        console.error('❌ Get software categories error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch categories'
        });
    }
});

// Delete software product
app.delete('/api/software/:id', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    const softwareId = req.params.id;

    try {
        // Use the appropriate database connection
        const dbConnection = promisePool || db;
        const executeQuery = promisePool ? 
            (query, params) => promisePool.execute(query, params) :
            (query, params) => db.query(query, params);

        // First check if the software product exists and belongs to the user
        const [softwareCheck] = await executeQuery(
            'SELECT software_id, user_id FROM software_products WHERE software_id = ?',
            [softwareId]
        );

        if (softwareCheck.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Software product not found'
            });
        }

        if (softwareCheck[0].user_id !== req.session.userId) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized: You can only delete your own software products'
            });
        }

        // Delete related records first (foreign key constraints)
        await executeQuery('DELETE FROM software_product_categories WHERE software_id = ?', [softwareId]);
        await executeQuery('DELETE FROM software_cart WHERE software_id = ?', [softwareId]);
        await executeQuery('DELETE FROM software_downloads WHERE software_id = ?', [softwareId]);
        await executeQuery('DELETE FROM software_reviews WHERE software_id = ?', [softwareId]);

        // Finally delete the software product
        await executeQuery('DELETE FROM software_products WHERE software_id = ?', [softwareId]);

        console.log(`✅ Software product ${softwareId} deleted successfully by user ${req.session.userId}`);

        res.json({
            success: true,
            message: 'Software product deleted successfully'
        });

    } catch (error) {
        console.error('❌ Delete software product error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete software product'
        });
    }
});

// Get single product details (supports both regular products and software products)
app.get('/api/product/:id', async (req, res) => {
    try {
        const productId = req.params.id;
        const { type = 'auto' } = req.query; // 'regular', 'software', or 'auto'
        
        // Use the appropriate database connection (promisePool for MySQL, db for PostgreSQL)
        const dbConnection = promisePool || db;
        const executeQuery = promisePool ? 
            (query, params) => promisePool.execute(query, params) :
            (query, params) => db.query(query, params);
        
        let product = null;
        
        // If type is 'software' or we need to check software table first
        if (type === 'software' || type === 'auto') {
            try {
                // Try to find in software products table first
                const [softwareProducts] = await executeQuery(`
                    SELECT 
                        sp.software_id as product_id,
                        sp.name,
                        sp.description,
                        sp.tagline,
                        'software' as category,
                        'New' as condition_item,
                        sp.price,
                        sp.image1_url,
                        sp.image2_url,
                        sp.image3_url,
                        null as image1,
                        null as image2,
                        null as image3,
                        sp.platform,
                        sp.tech_stack,
                        sp.developer_name,
                        sp.license_type,
                        sp.version,
                        sp.download_link,
                        sp.demo_link,
                        sp.github_link,
                        sp.documentation_link,
                        sp.features,
                        sp.system_requirements,
                        sp.downloads_count,
                        sp.views_count,
                        sp.created_at,
                        sp.user_id,
                        u.id as seller_id,
                        u.username as seller_name,
                        u.email as seller_email,
                        u.phone as seller_phone,
                        u.location as seller_location,
                        u.created_at as seller_member_since
                    FROM software_products sp
                    JOIN users u ON sp.user_id = u.id
                    WHERE sp.software_id = ? AND sp.is_active = true
                `, [productId]);

                if (softwareProducts.length > 0) {
                    product = softwareProducts[0];
                    product.is_software = true;
                    
                    // Get software reviews and rating
                    const [reviews] = await executeQuery(`
                        SELECT 
                            AVG(rating) as avg_rating,
                            COUNT(*) as review_count
                        FROM software_reviews 
                        WHERE software_id = ?
                    `, [productId]);

                    // Get seller statistics for software
                    const [sellerStats] = await executeQuery(`
                        SELECT 
                            COUNT(*) as total_items_sold,
                            AVG(4.5) as avg_rating
                        FROM software_products 
                        WHERE user_id = ? AND is_active = true
                    `, [product.user_id]);

                    // Increment view count
                    await executeQuery(`
                        UPDATE software_products 
                        SET views_count = views_count + 1 
                        WHERE software_id = ?
                    `, [productId]);

                    product.avg_rating = reviews[0]?.avg_rating || 4.5;
                    product.review_count = reviews[0]?.review_count || 0;
                    product.seller_stats = sellerStats[0];
                    product.views_count = (product.views_count || 0) + 1;
                }
            } catch (error) {
                console.warn('Software products table not available, checking regular products');
            }
        }
        
        // If not found in software table, try regular products table
        if (!product && (type === 'regular' || type === 'auto')) {
            const [products] = await executeQuery(`
                SELECT 
                    p.product_id,
                    p.name,
                    p.description,
                    p.price,
                    p.category,
                    p.condition_item,
                    p.image1_url,
                    p.image2_url,
                    p.image3_url,
                    p.image1,
                    p.image2,
                    p.image3,
                    p.created_at,
                    u.id as seller_id,
                    u.username as seller_name,
                    u.email as seller_email,
                    u.phone as seller_phone,
                    u.location as seller_location,
                    u.created_at as seller_member_since
                FROM products p
                JOIN users u ON p.user_id = u.id
                WHERE p.product_id = ?
            `, [productId]);

            if (products.length > 0) {
                product = products[0];
                product.is_software = false;
                
                // Get seller statistics (simplified to avoid table dependency issues)
                try {
                    const [sellerStats] = await executeQuery(`
                        SELECT 
                            COUNT(*) as total_items_sold,
                            4.5 as avg_rating
                        FROM products 
                        WHERE user_id = ?
                    `, [product.user_id]);

                    product.seller_stats = sellerStats[0];
                } catch (error) {
                    console.warn('Could not fetch seller stats:', error.message);
                    // Provide default seller stats if query fails
                    product.seller_stats = {
                        total_items_sold: 1,
                        avg_rating: 4.5
                    };
                }
            }
        }

        if (!product) {
            return res.status(404).json({
                success: false,
                message: 'Product not found'
            });
        }

        // Get product images with fallback
        const images = [];
        if (product.image1_url || product.image1) {
            images.push(product.image1_url || `data:image/jpeg;base64,${product.image1.toString('base64')}`);
        }
        if (product.image2_url || product.image2) {
            images.push(product.image2_url || `data:image/jpeg;base64,${product.image2.toString('base64')}`);
        }
        if (product.image3_url || product.image3) {
            images.push(product.image3_url || `data:image/jpeg;base64,${product.image3.toString('base64')}`);
        }

        // Add default image if no images available
        if (images.length === 0) {
            images.push(`https://via.placeholder.com/500x500/f8f9fa/666?text=${encodeURIComponent(product.name.substring(0, 20))}`);
        }

        // Format features if it's a JSON string
        let features = [];
        let systemRequirements = {};
        
        if (product.features) {
            try {
                features = JSON.parse(product.features);
            } catch (e) {
                features = product.features.split(',').map(f => f.trim()).filter(f => f);
            }
        }

        if (product.system_requirements) {
            try {
                systemRequirements = JSON.parse(product.system_requirements);
            } catch (e) {
                systemRequirements = { general: product.system_requirements };
            }
        }

        // Calculate member since year
        const memberSince = new Date(product.seller_member_since).getFullYear();

        // Prepare response
        const productDetail = {
            id: product.product_id,
            name: product.name,
            description: product.description,
            tagline: product.tagline,
            category: product.category,
            condition: product.condition_item,
            price: parseFloat(product.price),
            isFree: parseFloat(product.price) === 0,
            images: images,
            created_at: product.created_at,
            
            // Software specific fields
            platform: product.platform,
            techStack: product.tech_stack,
            developerName: product.developer_name,
            licenseType: product.license_type,
            version: product.version,
            downloadLink: product.download_link,
            demoLink: product.demo_link,
            githubLink: product.github_link,
            documentationLink: product.documentation_link,
            features: features,
            systemRequirements: systemRequirements,
            
            // Statistics (software specific)
            downloadsCount: product.downloads_count || 0,
            viewsCount: product.views_count || 0,
            avgRating: product.avg_rating || 4.5,
            reviewCount: product.review_count || 0,
            
            // Seller information
            seller: {
                id: product.seller_id,
                name: product.seller_name,
                email: product.seller_email,
                phone: product.seller_phone,
                location: product.seller_location,
                avatar: product.seller_name.charAt(0).toUpperCase(),
                rating: product.seller_stats?.avg_rating || 4.5,
                itemsSold: product.seller_stats?.total_items_sold || 0,
                totalDownloads: product.downloads_count || 0,
                memberSince: memberSince.toString()
            }
        };

        res.json({
            success: true,
            product: productDetail,
            source: product.is_software ? 'software_products' : 'products'
        });

    } catch (error) {
        console.error('❌ Get product detail error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch product details'
        });
    }
});

// Get user's sold items
app.get('/api/my-sold-items', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    try {
        const [soldItems] = await promisePool.execute(`
            SELECT 
                sold_id,
                original_product_id,
                name,
                description,
                price,
                category,
                condition_item,
                created_at,
                sold_at
            FROM sold_items 
            WHERE user_id = ?
            ORDER BY sold_at DESC
        `, [req.session.userId]);

        // Calculate total earnings
        const totalEarnings = soldItems.reduce((sum, item) => sum + parseFloat(item.price), 0);

        res.json({
            success: true,
            soldItems: soldItems,
            count: soldItems.length,
            totalEarnings: totalEarnings
        });

    } catch (error) {
        console.error('❌ Get sold items error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch sold items'
        });
    }
});

// Get user's cart items
app.get('/api/cart', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    try {
        // Get regular products from cart
        const [regularCartItems] = await promisePool.execute(`
            SELECT 
                c.cart_id,
                c.product_id,
                c.product_name,
                c.product_price,
                c.product_category,
                c.product_condition,
                c.product_description,
                c.seller_id,
                c.seller_name,
                c.product_image_url,
                c.product_image,
                c.quantity,
                c.added_at,
                u.phone as seller_phone,
                'regular' as product_type
            FROM cart c
            LEFT JOIN users u ON c.seller_id = u.id
            WHERE c.user_id = ?
        `, [req.session.userId]);

        // Get software products from software_cart
        let softwareCartItems = [];
        try {
            const [softwareItems] = await promisePool.execute(`
                SELECT 
                    sc.cart_id,
                    sc.software_id as product_id,
                    sp.name as product_name,
                    sp.price as product_price,
                    'software' as product_category,
                    'New' as product_condition,
                    sp.description as product_description,
                    sp.user_id as seller_id,
                    u.username as seller_name,
                    sp.image1_url as product_image_url,
                    null as product_image,
                    1 as quantity,
                    sc.added_at,
                    u.phone as seller_phone,
                    'software' as product_type,
                    sp.platform,
                    sp.tech_stack
                FROM software_cart sc
                JOIN software_products sp ON sc.software_id = sp.software_id
                LEFT JOIN users u ON sp.user_id = u.id
                WHERE sc.user_id = ?
            `, [req.session.userId]);
            softwareCartItems = softwareItems;
        } catch (error) {
            console.warn('Software cart table not available:', error.message);
        }

        // Combine both cart types
        const allCartItems = [...regularCartItems, ...softwareCartItems];

        // Return images from Cloudinary URLs or fallback to base64 for backward compatibility
        const cartItemsWithImages = allCartItems.map(item => ({
            ...item,
            product_image: item.product_image_url || (item.product_image ? `data:image/jpeg;base64,${item.product_image.toString('base64')}` : null),
            // Remove URL field from response
            product_image_url: undefined
        }));

        // Sort by added_at DESC
        cartItemsWithImages.sort((a, b) => new Date(b.added_at) - new Date(a.added_at));

        // Calculate total
        const total = cartItemsWithImages.reduce((sum, item) => sum + (parseFloat(item.product_price) * (item.quantity || 1)), 0);

        res.json({
            success: true,
            cartItems: cartItemsWithImages,
            count: cartItemsWithImages.length,
            total: total
        });

    } catch (error) {
        console.error('❌ Get cart items error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch cart items'
        });
    }
});

// Get cart count only (for efficiency)
app.get('/api/cart/count', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    try {
        // Get regular cart count
        const [regularResult] = await promisePool.execute(
            'SELECT COUNT(*) as count FROM cart WHERE user_id = ?',
            [req.session.userId]
        );

        let regularCount = regularResult[0].count;
        let softwareCount = 0;

        // Get software cart count
        try {
            const [softwareResult] = await promisePool.execute(
                'SELECT COUNT(*) as count FROM software_cart WHERE user_id = ?',
                [req.session.userId]
            );
            softwareCount = softwareResult[0].count;
        } catch (error) {
            console.warn('Software cart table not available:', error.message);
        }

        const totalCount = regularCount + softwareCount;

        res.json({
            success: true,
            count: totalCount,
            regularCount: regularCount,
            softwareCount: softwareCount
        });
    } catch (error) {
        console.error('❌ Get cart count error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch cart count'
        });
    }
});

// Add item to cart (supports both regular products and software products)
app.post('/api/cart/add', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    const { productId, productType = 'auto' } = req.body; // 'regular', 'software', or 'auto'

    try {
        let product = null;
        let tableName = '';
        
        // Check software products first if type is 'software' or 'auto'
        if (productType === 'software' || productType === 'auto') {
            try {
                const [softwareProducts] = await promisePool.execute(`
                    SELECT 
                        sp.software_id as product_id,
                        sp.name,
                        sp.price,
                        'software' as category,
                        'New' as condition_item,
                        sp.description,
                        sp.tagline,
                        sp.image1_url,
                        null as image1,
                        sp.user_id as seller_id,
                        u.username as seller_name
                    FROM software_products sp
                    JOIN users u ON sp.user_id = u.id
                    WHERE sp.software_id = ? AND sp.is_active = true
                `, [productId]);

                if (softwareProducts.length > 0) {
                    product = softwareProducts[0];
                    tableName = 'software_cart';
                }
            } catch (error) {
                console.warn('Software products table not available, checking regular products');
            }
        }
        
        // Check regular products if not found in software or type is 'regular'
        if (!product && (productType === 'regular' || productType === 'auto')) {
            const [products] = await promisePool.execute(`
                SELECT 
                    p.product_id,
                    p.name,
                    p.price,
                    p.category,
                    p.condition_item,
                    p.description,
                    p.image1_url,
                    p.image1,
                    p.user_id as seller_id,
                    u.username as seller_name
                FROM products p
                JOIN users u ON p.user_id = u.id
                WHERE p.product_id = ?
            `, [productId]);

            if (products.length > 0) {
                product = products[0];
                tableName = 'cart';
            }
        }

        if (!product) {
            return res.status(404).json({
                success: false,
                message: 'Product not found'
            });
        }

        // Check if user is trying to add their own product
        if (product.seller_id === req.session.userId) {
            return res.status(400).json({
                success: false,
                message: 'You cannot add your own product to cart'
            });
        }

        // Handle software cart (separate table)
        if (tableName === 'software_cart') {
            // Check if software already exists in cart
            const [existingItems] = await promisePool.execute(
                'SELECT cart_id FROM software_cart WHERE user_id = ? AND software_id = ?',
                [req.session.userId, productId]
            );

            if (existingItems.length > 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Software already in cart'
                });
            }

            // Add new software to cart
            await promisePool.execute(`
                INSERT INTO software_cart (
                    user_id, software_id, software_name, software_price,
                    software_description, seller_id, seller_name, software_image_url
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `, [
                req.session.userId,
                product.product_id,
                product.name,
                product.price,
                product.description || product.tagline,
                product.seller_id,
                product.seller_name,
                product.image1_url
            ]);
        } else {
            // Handle regular products cart
            // Check if item already exists in cart
            const [existingItems] = await promisePool.execute(
                'SELECT cart_id, quantity FROM cart WHERE user_id = ? AND product_id = ?',
                [req.session.userId, productId]
            );

            if (existingItems.length > 0) {
                // Update quantity if item already exists
                await promisePool.execute(
                    'UPDATE cart SET quantity = quantity + 1 WHERE cart_id = ?',
                    [existingItems[0].cart_id]
                );
            } else {
                // Determine which image to use (Cloudinary URL or fallback to BLOB)
                const productImageUrl = product.image1_url;
                const productImageBlob = productImageUrl ? null : product.image1; // Only use BLOB if no URL
                
                // Add new item to cart
                await promisePool.execute(`
                    INSERT INTO cart (
                        user_id, product_id, product_name, product_price,
                        product_category, product_condition, product_description,
                        seller_id, seller_name, product_image_url, product_image, quantity
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                `, [
                    req.session.userId,
                    product.product_id,
                    product.name,
                    product.price,
                    product.category,
                    product.condition_item,
                    product.description,
                    product.seller_id,
                    product.seller_name,
                    productImageUrl,
                    productImageBlob
                ]);
            }
        }

        res.json({
            success: true,
            message: `${tableName === 'software_cart' ? 'Software' : 'Item'} added to cart successfully`
        });

    } catch (error) {
        console.error('❌ Add to cart error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add item to cart'
        });
    }
});

// Update cart item quantity
app.put('/api/cart/:cartId', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    const { cartId } = req.params;
    const { quantity } = req.body;

    try {
        // Verify cart item belongs to user
        const [cartItems] = await promisePool.execute(
            'SELECT user_id FROM cart WHERE cart_id = ?',
            [cartId]
        );

        if (cartItems.length === 0 || cartItems[0].user_id !== req.session.userId) {
            return res.status(403).json({
                success: false,
                message: 'Cart item not found or unauthorized'
            });
        }

        if (quantity <= 0) {
            // Remove item if quantity is 0 or negative
            await promisePool.execute(
                'DELETE FROM cart WHERE cart_id = ?',
                [cartId]
            );
        } else {
            // Update quantity
            await promisePool.execute(
                'UPDATE cart SET quantity = ? WHERE cart_id = ?',
                [quantity, cartId]
            );
        }

        res.json({
            success: true,
            message: 'Cart updated successfully'
        });

    } catch (error) {
        console.error('❌ Update cart error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update cart'
        });
    }
});

// Remove item from cart
app.delete('/api/cart/:cartId', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    const { cartId } = req.params;
    const { productType } = req.query; // 'regular' or 'software'

    try {
        let tableName = 'cart';
        let itemFound = false;

        // Try to find in regular cart first
        const [regularCartItems] = await promisePool.execute(
            'SELECT user_id FROM cart WHERE cart_id = ?',
            [cartId]
        );

        if (regularCartItems.length > 0) {
            if (regularCartItems[0].user_id !== req.session.userId) {
                return res.status(403).json({
                    success: false,
                    message: 'Cart item not found or unauthorized'
                });
            }
            tableName = 'cart';
            itemFound = true;
        } else {
            // Try software cart
            try {
                const [softwareCartItems] = await promisePool.execute(
                    'SELECT user_id FROM software_cart WHERE cart_id = ?',
                    [cartId]
                );

                if (softwareCartItems.length > 0) {
                    if (softwareCartItems[0].user_id !== req.session.userId) {
                        return res.status(403).json({
                            success: false,
                            message: 'Cart item not found or unauthorized'
                        });
                    }
                    tableName = 'software_cart';
                    itemFound = true;
                }
            } catch (error) {
                console.warn('Software cart table not available:', error.message);
            }
        }

        if (!itemFound) {
            return res.status(404).json({
                success: false,
                message: 'Cart item not found'
            });
        }

        // Remove item from appropriate cart table
        await promisePool.execute(
            `DELETE FROM ${tableName} WHERE cart_id = ?`,
            [cartId]
        );

        res.json({
            success: true,
            message: `Item removed from cart successfully`
        });

    } catch (error) {
        console.error('❌ Remove from cart error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to remove item from cart'
        });
    }
});

// Get a single product for editing
app.get('/api/products/:productId', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    const { productId } = req.params;

    try {
        // Get the product with user verification
        const [products] = await promisePool.execute(
            'SELECT * FROM products WHERE product_id = ? AND user_id = ?',
            [productId, req.session.userId]
        );

        if (products.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Product not found or you do not have permission to edit it'
            });
        }

        res.json({
            success: true,
            product: products[0]
        });

    } catch (error) {
        console.error('❌ Get product error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to get product details'
        });
    }
});

// Update a product
app.put('/api/products/:productId', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    const { productId } = req.params;
    const { name, description, price, category, condition, image1_url, image2_url, image3_url } = req.body;

    // Validate required fields
    if (!name || !category || !condition) {
        return res.status(400).json({ 
            success: false, 
            message: 'Name, category, and condition are required' 
        });
    }

    // Validate price (if provided)
    let finalPrice = 0;
    if (price && price !== '') {
        if (isNaN(price) || parseFloat(price) < 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Please enter a valid price' 
            });
        }
        finalPrice = parseFloat(price);
    }

    try {
        // First, verify that the product belongs to the logged-in user
        const [existingProducts] = await promisePool.execute(
            'SELECT * FROM products WHERE product_id = ? AND user_id = ?',
            [productId, req.session.userId]
        );

        if (existingProducts.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Product not found or you do not have permission to edit it'
            });
        }

        const existingProduct = existingProducts[0];
        
        // Use provided image URLs or keep existing ones
        const imageUrls = {
            image1_url: image1_url || existingProduct.image1_url,
            image2_url: image2_url || existingProduct.image2_url,
            image3_url: image3_url || existingProduct.image3_url
        };

        console.log(`📤 Updating product "${name}" (ID: ${productId})`);
        console.log('📸 Image URLs:', imageUrls);

        // Update the product
        await promisePool.execute(
            'UPDATE products SET name = ?, description = ?, price = ?, category = ?, condition_item = ?, image1_url = ?, image2_url = ?, image3_url = ?, updated_at = CURRENT_TIMESTAMP WHERE product_id = ? AND user_id = ?',
            [name, description || '', finalPrice, category, condition, imageUrls.image1_url, imageUrls.image2_url, imageUrls.image3_url, productId, req.session.userId]
        );

        console.log(`✅ Product "${name}" updated successfully (ID: ${productId})`);

        res.json({
            success: true,
            message: 'Product updated successfully!',
            productId: productId,
            images: imageUrls
        });

    } catch (error) {
        console.error('❌ Update product error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update product. Please try again.'
        });
    }
});

// Update a software product
app.put('/api/software/:softwareId', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    const { softwareId } = req.params;

    try {
        const {
            name,
            description,
            tagline,
            price,
            image1_url,
            image2_url,
            image3_url,
            platform,
            tech_stack,
            developer_name,
            license_type,
            version,
            download_link,
            demo_link,
            github_link,
            documentation_link,
            features,
            system_requirements,
            categories
        } = req.body;

        // First, verify that the software product belongs to the logged-in user
        const [existingSoftware] = await promisePool.execute(
            'SELECT * FROM software_products WHERE id = ? AND user_id = ?',
            [softwareId, req.session.userId]
        );

        if (existingSoftware.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Software product not found or you do not have permission to edit it'
            });
        }

        const existingProduct = existingSoftware[0];
        
        // Use provided image URLs or keep existing ones
        const imageUrls = {
            image1_url: image1_url || existingProduct.image1_url,
            image2_url: image2_url || existingProduct.image2_url,
            image3_url: image3_url || existingProduct.image3_url
        };

        console.log(`📤 Updating software product "${name}" (ID: ${softwareId})`);
        console.log('📸 Image URLs:', imageUrls);

        // Update software product
        await promisePool.execute(`
            UPDATE software_products SET 
                name = ?, description = ?, tagline = ?, price = ?,
                image1_url = ?, image2_url = ?, image3_url = ?,
                platform = ?, tech_stack = ?, developer_name = ?, license_type = ?, version = ?,
                download_link = ?, demo_link = ?, github_link = ?, documentation_link = ?,
                features = ?, system_requirements = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
        `, [
            name, description, tagline, price || 0,
            imageUrls.image1_url, imageUrls.image2_url, imageUrls.image3_url,
            platform, tech_stack, developer_name, license_type, version || '1.0.0',
            download_link, demo_link, github_link, documentation_link,
            JSON.stringify(features || []), JSON.stringify(system_requirements || {}),
            softwareId, req.session.userId
        ]);

        // Update categories if provided
        if (categories && categories.length > 0) {
            // Remove existing categories
            await promisePool.execute(
                'DELETE FROM software_categories WHERE software_id = ?',
                [softwareId]
            );

            // Add new categories
            for (const categoryName of categories) {
                try {
                    // Get or create category
                    let [categoryResult] = await promisePool.execute(
                        'SELECT id FROM categories WHERE name = ?',
                        [categoryName]
                    );

                    let categoryId;
                    if (categoryResult.length === 0) {
                        const [insertResult] = await promisePool.execute(
                            'INSERT INTO categories (name) VALUES (?)',
                            [categoryName]
                        );
                        categoryId = insertResult.insertId;
                    } else {
                        categoryId = categoryResult[0].id;
                    }

                    // Link software to category
                    await promisePool.execute(
                        'INSERT INTO software_categories (software_id, category_id) VALUES (?, ?)',
                        [softwareId, categoryId]
                    );
                } catch (categoryError) {
                    console.error(`❌ Error updating category ${categoryName}:`, categoryError);
                }
            }
        }

        console.log(`✅ Software product "${name}" updated successfully (ID: ${softwareId})`);

        res.json({
            success: true,
            message: 'Software product updated successfully!',
            softwareId: softwareId,
            images: imageUrls
        });

    } catch (error) {
        console.error('❌ Update software product error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update software product. Please try again.'
        });
    }
});

// Delete a product
app.delete('/api/products/:productId', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    const { productId } = req.params;

    try {
        // First, verify that the product belongs to the logged-in user
        const [products] = await promisePool.execute(
            'SELECT user_id FROM products WHERE product_id = ?',
            [productId]
        );

        if (products.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Product not found'
            });
        }

        if (products[0].user_id !== req.session.userId) {
            return res.status(403).json({
                success: false,
                message: 'You can only delete your own products'
            });
        }

        // Delete the product
        const [result] = await promisePool.execute(
            'DELETE FROM products WHERE product_id = ? AND user_id = ?',
            [productId, req.session.userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Product not found or already deleted'
            });
        }

        console.log(`✅ Product deleted: ID ${productId} by user ${req.session.userId}`);

        res.json({
            success: true,
            message: 'Product deleted successfully'
        });

    } catch (error) {
        console.error('❌ Delete product error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete product'
        });
    }
});

// Mark product as sold - move to sold_items table
app.post('/api/products/:productId/mark-sold', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    const { productId } = req.params;

    try {
        // First, get the product details and verify ownership
        const [products] = await promisePool.execute(
            'SELECT * FROM products WHERE product_id = ? AND user_id = ?',
            [productId, req.session.userId]
        );

        if (products.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Product not found or you do not have permission to modify it'
            });
        }

        const product = products[0];

        // Begin transaction using promisePool
        const connection = await promisePool.getConnection();
        
        try {
            await connection.beginTransaction();

            // Insert into sold_items table (without images)
            await connection.execute(`
                INSERT INTO sold_items (
                    user_id, original_product_id, name, category, 
                    condition_item, description, price, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `, [
                product.user_id,
                product.product_id,
                product.name,
                product.category,
                product.condition_item,
                product.description,
                product.price,
                product.created_at
            ]);

            // Delete from products table
            await connection.execute(
                'DELETE FROM products WHERE product_id = ? AND user_id = ?',
                [productId, req.session.userId]
            );

            // Commit transaction
            await connection.commit();
            connection.release();

            console.log(`✅ Product marked as sold: ID ${productId} by user ${req.session.userId}`);

            res.json({
                success: true,
                message: 'Product marked as sold successfully'
            });

        } catch (transactionError) {
            // Rollback transaction on error
            await connection.rollback();
            connection.release();
            throw transactionError;
        }

    } catch (error) {
        console.error('❌ Mark as sold error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to mark product as sold'
        });
    }
});

// ================================
// ADMIN PANEL ROUTES
// ================================

// Admin authentication middleware
function requireAdmin(req, res, next) {
    // Check if user is logged in and has admin privileges
    if (!req.session.userId || !req.session.isAdmin) {
        return res.status(401).json({
            success: false,
            message: 'Admin authentication required'
        });
    }
    
    next();
}

// Admin login page
app.get('/admin-login', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-login.html'));
});

// Admin login handler
app.post('/admin-login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Get admin credentials from environment variables
        const adminUsername = config.admin.username;
        const adminPassword = config.admin.password;
        
        // Verify admin credentials
        if (username === adminUsername && password === adminPassword) {
            // Set admin session
            req.session.isAdmin = true;
            req.session.adminUsername = username;
            req.session.userId = 'admin'; // Set a dummy user ID for admin
            
            console.log(`✅ Admin login successful: ${username}`);
            
            res.json({
                success: true,
                message: 'Admin login successful'
            });
        } else {
            console.log(`❌ Admin login failed: ${username}`);
            
            res.status(401).json({
                success: false,
                message: 'Invalid admin credentials'
            });
        }
        
    } catch (error) {
        console.error('❌ Admin login error:', error);
        res.status(500).json({
            success: false,
            message: 'Login failed'
        });
    }
});

// Admin logout
app.post('/admin-logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('❌ Admin logout error:', err);
            return res.status(500).json({
                success: false,
                message: 'Logout failed'
            });
        }
        
        res.json({
            success: true,
            message: 'Logged out successfully'
        });
    });
});

// Admin panel access route (protected)
app.get('/admin', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// Admin Dashboard Data
// Add admin dashboard endpoint after the existing admin routes
// Add this dashboard endpoint - just copy and paste this block into your app.js file
// Admin Dashboard Data - Fixed to work with your current database schema
app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
    try {
        // Get total users
        const [userResult] = await promisePool.execute('SELECT COUNT(*) as count FROM users');
        const totalUsers = userResult[0].count;

        // Get total products - Remove the is_active check since column doesn't exist
        const [productResult] = await promisePool.execute('SELECT COUNT(*) as count FROM products');
        const totalProducts = productResult[0].count;

        // Get total software products - Remove is_active check
        let totalSoftware = 0;
        try {
            const [softwareResult] = await promisePool.execute('SELECT COUNT(*) as count FROM software_products');
            totalSoftware = softwareResult[0].count;
        } catch (err) {
            console.warn('Software products table not available:', err.message);
        }

        // Get total sold items
        const [soldResult] = await promisePool.execute('SELECT COUNT(*) as count, COALESCE(SUM(price), 0) as revenue FROM sold_items');
        const productsSold = soldResult[0].count || 0;
        const totalRevenue = soldResult[0].revenue || 0;

        // Get free donations - Remove is_active check
        const [donationResult] = await promisePool.execute('SELECT COUNT(*) as count FROM products WHERE price = 0');
        const freeDonations = donationResult[0].count;

        // Get active users today
        const [activeResult] = await promisePool.execute(
            'SELECT COUNT(DISTINCT user_id) as count FROM products WHERE DATE(created_at) = CURDATE()'
        );
        const activeToday = activeResult[0].count;

        // Get recent products (last 5) - Remove is_active check
        const [recentProducts] = await promisePool.execute(`
            SELECT 
                p.product_id, p.name, p.price, p.category, p.created_at, 
                u.username as seller_name, 'product' as type
            FROM products p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
            LIMIT 5
        `);

        // Get recent software (last 5) - Remove is_active check
        let recentSoftware = [];
        try {
            const [softwareItems] = await promisePool.execute(`
                SELECT 
                    s.software_id as product_id, s.name, s.price, 
                    'Software' as category, s.created_at,
                    u.username as seller_name, 'software' as type
                FROM software_products s
                JOIN users u ON s.user_id = u.id
                ORDER BY s.created_at DESC
                LIMIT 5
            `);
            recentSoftware = softwareItems;
        } catch (err) {
            console.warn('Error fetching recent software:', err.message);
        }

        // Combine and sort recent activity
        const recentActivity = [...recentProducts, ...recentSoftware]
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
            .slice(0, 5)
            .map(item => ({
                type: 'product_listed',
                message: `New ${item.type} listed: ${item.name}`,
                timestamp: item.created_at
            }));

        res.json({
            success: true,
            data: {
                totalUsers,
                totalProducts: totalProducts + totalSoftware,
                productsSold,
                totalRevenue,
                freeDonations,
                activeToday,
                recentActivity
            }
        });
    } catch (error) {
        console.error('Dashboard Error:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching dashboard data'
        });
    }
});

// Get all users
app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const [users] = await promisePool.execute(`
            SELECT 
                u.*,
                COUNT(p.product_id) as product_count
            FROM users u
            LEFT JOIN products p ON u.id = p.user_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        `);

        res.json({
            success: true,
            users: users
        });

    } catch (error) {
        console.error('❌ Admin users error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load users'
        });
    }
});

// Get all products
app.get('/api/admin/products', requireAdmin, async (req, res) => {
    try {
        // Fetch regular products
        const [products] = await promisePool.execute(`
            SELECT 
                p.*,
                u.username,
                'regular' as product_type,
                CASE WHEN s.original_product_id IS NOT NULL THEN 1 ELSE 0 END as is_sold
            FROM products p
            JOIN users u ON p.user_id = u.id
            LEFT JOIN sold_items s ON p.product_id = s.original_product_id
            ORDER BY p.created_at DESC
        `);

        // Fetch software products
        const [softwareProducts] = await promisePool.execute(`
            SELECT 
                sp.software_id as product_id,
                sp.name,
                sp.description,
                sp.price,
                sp.image1_url,
                sp.image2_url,
                sp.image3_url,
                sp.platform,
                sp.tech_stack,
                sp.version,
                sp.user_id,
                sp.created_at,
                sp.updated_at,
                u.username,
                'software' as product_type,
                'Software' as category,
                'N/A' as condition_item,
                0 as is_sold
            FROM software_products sp
            JOIN users u ON sp.user_id = u.id
            ORDER BY sp.created_at DESC
        `);

        // Process regular products
        const processedProducts = products.map(product => {
            const productCopy = { ...product };
            
            // Use Cloudinary URL first, fallback to base64 from BLOB
            productCopy.image1 = product.image1_url || (product.image1 ? `data:image/jpeg;base64,${product.image1.toString('base64')}` : null);
            productCopy.image2 = product.image2_url || (product.image2 ? `data:image/jpeg;base64,${product.image2.toString('base64')}` : null);
            productCopy.image3 = product.image3_url || (product.image3 ? `data:image/jpeg;base64,${product.image3.toString('base64')}` : null);
            
            // Remove URL fields and BLOB fields from response for cleaner API
            delete productCopy.image1_url;
            delete productCopy.image2_url;
            delete productCopy.image3_url;
            
            return productCopy;
        });

        // Process software products
        const processedSoftwareProducts = softwareProducts.map(software => {
            const softwareCopy = { ...software };
            
            // Use Cloudinary URL
            softwareCopy.image1 = software.image1_url || null;
            softwareCopy.image2 = software.image2_url || null;
            softwareCopy.image3 = software.image3_url || null;
            
            // Remove URL fields from response for cleaner API
            delete softwareCopy.image1_url;
            delete softwareCopy.image2_url;
            delete softwareCopy.image3_url;
            
            return softwareCopy;
        });

        // Combine both product types and sort by created_at
        const allProducts = [...processedProducts, ...processedSoftwareProducts]
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        res.json({
            success: true,
            products: allProducts
        });

    } catch (error) {
        console.error('❌ Admin products error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load products'
        });
    }
});

// Get all sales
app.get('/api/admin/sales', requireAdmin, async (req, res) => {
    try {
        const [sales] = await promisePool.execute(`
            SELECT 
                s.sold_id as id,
                s.name as product_name,
                s.price as sale_price,
                s.sold_at,
                s.category,
                s.condition_item,
                u.username as seller_name,
                'N/A' as buyer_name
            FROM sold_items s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.sold_at DESC
        `);

        res.json({
            success: true,
            sales: sales
        });

    } catch (error) {
        console.error('❌ Admin sales error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load sales'
        });
    }
});

// Get analytics data
app.get('/api/admin/analytics', requireAdmin, async (req, res) => {
    try {
        // Category statistics
        const [categoryStats] = await promisePool.execute(`
            SELECT category, COUNT(*) as count
            FROM products
            GROUP BY category
        `);

        // New users this month
        const [newUsersResult] = await promisePool.execute(`
            SELECT COUNT(*) as count
            FROM users
            WHERE MONTH(created_at) = MONTH(CURDATE()) 
            AND YEAR(created_at) = YEAR(CURDATE())
        `);

        // Revenue this month - fixed field name
        const [revenueResult] = await promisePool.execute(`
            SELECT COALESCE(SUM(price), 0) as total
            FROM sold_items
            WHERE MONTH(sold_at) = MONTH(CURDATE()) 
            AND YEAR(sold_at) = YEAR(CURDATE())
        `);

        const categoryStatsObj = {};
        categoryStats.forEach(stat => {
            categoryStatsObj[stat.category] = stat.count;
        });

        res.json({
            success: true,
            analytics: {
                categoryStats: categoryStatsObj,
                newUsersThisMonth: newUsersResult[0].count,
                revenueThisMonth: revenueResult[0].total
            }
        });

    } catch (error) {
        console.error('❌ Admin analytics error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load analytics'
        });
    }
});

// Delete product (admin)
app.delete('/api/admin/products/:productId', requireAdmin, async (req, res) => {
    try {
        const { productId } = req.params;

        // First check if product exists
        const [product] = await promisePool.execute(
            'SELECT * FROM products WHERE product_id = ?',
            [productId]
        );

        if (product.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Product not found'
            });
        }

        // Delete from cart first (foreign key constraint)
        await promisePool.execute(
            'DELETE FROM cart WHERE product_id = ?',
            [productId]
        );

        // Delete from sold_items if exists
        await promisePool.execute(
            'DELETE FROM sold_items WHERE original_product_id = ?',
            [productId]
        );

        // Delete the product
        await promisePool.execute(
            'DELETE FROM products WHERE product_id = ?',
            [productId]
        );

        console.log(`✅ Admin deleted product: ID ${productId}`);

        res.json({
            success: true,
            message: 'Product deleted successfully'
        });

    } catch (error) {
        console.error('❌ Admin delete product error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete product'
        });
    }
});

// Delete user (admin)
app.delete('/api/admin/users/:userId', requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;

        // First check if user exists
        const [user] = await promisePool.execute(
            'SELECT * FROM users WHERE id = ?',
            [userId]
        );

        if (user.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Use transaction for data integrity
        const connection = await promisePool.getConnection();
        await connection.beginTransaction();

        try {
            // Delete from cart
            await connection.execute('DELETE FROM cart WHERE user_id = ?', [userId]);
            
            // Delete from sold_items (user_id represents the seller in this table)
            await connection.execute('DELETE FROM sold_items WHERE user_id = ?', [userId]);
            
            // Delete products (will cascade to cart and sold_items due to foreign keys)
            await connection.execute('DELETE FROM products WHERE user_id = ?', [userId]);
            
            // Delete user
            await connection.execute('DELETE FROM users WHERE id = ?', [userId]);

            await connection.commit();
            connection.release();

            console.log(`✅ Admin deleted user: ID ${userId}`);

            res.json({
                success: true,
                message: 'User deleted successfully'
            });

        } catch (transactionError) {
            await connection.rollback();
            connection.release();
            throw transactionError;
        }

    } catch (error) {
        console.error('❌ Admin delete user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete user'
        });
    }
});

// Update user (admin)
app.put('/api/admin/users/:userId', requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { username, phone, location } = req.body;

        // Validate required fields
        if (!username) {
            return res.status(400).json({
                success: false,
                message: 'Username is required'
            });
        }

        // First check if user exists
        const [existingUser] = await promisePool.execute(
            'SELECT * FROM users WHERE id = ?',
            [userId]
        );

        if (existingUser.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if username is already taken by another user
        const [duplicateUser] = await promisePool.execute(
            'SELECT id FROM users WHERE username = ? AND id != ?',
            [username, userId]
        );

        if (duplicateUser.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'Username is already taken by another user'
            });
        }

        // Update user
        await promisePool.execute(
            'UPDATE users SET username = ?, phone = ?, location = ? WHERE id = ?',
            [username, phone || null, location || null, userId]
        );

        console.log(`✅ Admin updated user: ID ${userId}`);

        res.json({
            success: true,
            message: 'User updated successfully'
        });

    } catch (error) {
        console.error('❌ Admin update user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user'
        });
    }
});

// Export data (admin)
app.get('/api/admin/export', requireAdmin, async (req, res) => {
    try {
        const [users] = await promisePool.execute('SELECT * FROM users');
        const [products] = await promisePool.execute('SELECT * FROM products');
        const [sales] = await promisePool.execute('SELECT * FROM sold_items');

        const exportData = {
            users,
            products,
            sales,
            exportDate: new Date().toISOString()
        };

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', 'attachment; filename=educycle-data-export.json');
        res.json(exportData);

    } catch (error) {
        console.error('❌ Admin export error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to export data'
        });
    }
});

// Clear cache (admin)
app.post('/api/admin/clear-cache', requireAdmin, async (req, res) => {
    try {
        // In a real application, you would clear your cache here
        // For now, we'll just return success
        console.log(`✅ Admin cleared cache`);

        res.json({
            success: true,
            message: 'Cache cleared successfully'
        });

    } catch (error) {
        console.error('❌ Admin clear cache error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to clear cache'
        });
    }
});

// Generate report (admin)
app.get('/api/admin/report', requireAdmin, async (req, res) => {
    try {
        const [dashboardData] = await Promise.all([
            Promise.all([
                promisePool.execute('SELECT COUNT(*) as count FROM users'),
                promisePool.execute('SELECT COUNT(*) as count FROM products'),
                promisePool.execute('SELECT COUNT(*) as count FROM sold_items'),
                promisePool.execute('SELECT COALESCE(SUM(price), 0) as total FROM sold_items'),
                promisePool.execute('SELECT COUNT(*) as count FROM products WHERE price = 0')
            ])
        ]);

        const [
            [totalUsersResult],
            [totalProductsResult],
            [productsSoldResult],
            [totalRevenueResult],
            [freeDonationsResult]
        ] = dashboardData[0];

        const reportHtml = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>EduCycle Platform Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; }
                    .header { text-align: center; margin-bottom: 40px; }
                    .stats { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
                    .stat-card { border: 1px solid #ddd; padding: 20px; border-radius: 8px; }
                    .stat-number { font-size: 2em; color: #52ab98; font-weight: bold; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>EduCycle Platform Report</h1>
                    <p>Generated on: ${new Date().toLocaleDateString()}</p>
                </div>
                <div class="stats">
                    <div class="stat-card">
                        <h3>Total Users</h3>
                        <div class="stat-number">${totalUsersResult[0].count}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Total Products</h3>
                        <div class="stat-number">${totalProductsResult[0].count}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Products Sold</h3>
                        <div class="stat-number">${productsSoldResult[0].count}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Total Revenue</h3>
                        <div class="stat-number">₹${totalRevenueResult[0].total}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Free Donations</h3>
                        <div class="stat-number">${freeDonationsResult[0].count}</div>
                    </div>
                </div>
            </body>
            </html>
        `;

        res.setHeader('Content-Type', 'text/html');
        res.send(reportHtml);

    } catch (error) {
        console.error('❌ Admin report error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to generate report'
        });
    }
});

// System information (admin)
app.get('/api/admin/system-info', requireAdmin, async (req, res) => {
    try {
        // Get database table sizes and row counts
        const [tableStats] = await promisePool.execute(`
            SELECT 
                TABLE_NAME as table_name,
                TABLE_ROWS as row_count,
                ROUND(((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024), 2) as size_mb
            FROM information_schema.TABLES 
            WHERE TABLE_SCHEMA = DATABASE() 
            ORDER BY size_mb DESC
        `);

        // Calculate total storage
        const totalStorageMB = tableStats.reduce((sum, table) => sum + (parseFloat(table.size_mb) || 0), 0);

        // Get active sessions count (approximate using recent user activity)
        const [activeSessions] = await promisePool.execute(`
            SELECT COUNT(DISTINCT user_id) as active_count
            FROM (
                SELECT user_id FROM products WHERE created_at > NOW() - INTERVAL 1 HOUR
                UNION
                SELECT user_id FROM sold_items WHERE sold_at > NOW() - INTERVAL 1 HOUR
                UNION
                SELECT user_id FROM cart WHERE cart_id IN (
                    SELECT cart_id FROM cart WHERE cart_id > (
                        SELECT MAX(cart_id) - 100 FROM cart
                    )
                )
            ) as recent_activity
        `);

        // Get database connection info
        const [dbInfo] = await promisePool.execute('SELECT VERSION() as version');

        // Get recent backup info (simulated - you can implement actual backup logic)
        const lastBackup = new Date(Date.now() - (Math.random() * 7 * 24 * 60 * 60 * 1000)); // Random date within last week

        const systemInfo = {
            database: {
                status: 'Connected',
                version: dbInfo[0].version,
                totalTables: tableStats.length,
                totalStorageMB: totalStorageMB.toFixed(2),
                tableStats: tableStats.slice(0, 10) // Top 10 tables
            },
            sessions: {
                activeCount: activeSessions[0].active_count || 0,
                lastHour: activeSessions[0].active_count || 0
            },
            backup: {
                lastBackup: lastBackup.toISOString(),
                status: 'Automated'
            },
            server: {
                uptime: process.uptime(),
                nodeVersion: process.version,
                platform: process.platform,
                memory: {
                    used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
                    total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024)
                }
            }
        };

        console.log('✅ Admin system info retrieved');

        res.json({
            success: true,
            systemInfo: systemInfo
        });

    } catch (error) {
        console.error('❌ Admin system info error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to retrieve system information'
        });
    }
});

// Clear cache (admin)
app.post('/api/admin/clear-cache', requireAdmin, async (req, res) => {
    try {
        // Simulate cache clearing (you can implement actual cache logic)
        console.log('✅ Admin cleared cache');

        res.json({
            success: true,
            message: 'Cache cleared successfully'
        });

    } catch (error) {
        console.error('❌ Admin clear cache error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to clear cache'
        });
    }
});
// Add these endpoints to your app.js

// Get software details endpoint
app.get('/api/software/:id', async (req, res) => {
    try {
        const [software] = await promisePool.execute(`
            SELECT s.*, u.username as seller_name 
            FROM software_products s
            JOIN users u ON s.user_id = u.id
            WHERE s.software_id = ? AND s.is_active = 1
        `, [req.params.id]);

        if (software.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Software not found'
            });
        }

        res.json({
            success: true,
            software: software[0]
        });
    } catch (error) {
        console.error('Error fetching software:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching software details'
        });
    }
});

// Record software download endpoint
app.post('/api/software/:id/download', requireLogin, async (req, res) => {
    try {
        // Update download count
        await promisePool.execute(`
            UPDATE software_products 
            SET downloads_count = downloads_count + 1 
            WHERE software_id = ?
        `, [req.params.id]);

        res.json({
            success: true,
            message: 'Download recorded successfully'
        });
    } catch (error) {
        console.error('Error recording download:', error);
        // Don't fail the download if tracking fails
        res.json({
            success: true,
            message: 'Download initiated'
        });
    }
});
// ================================
// END ADMIN PANEL ROUTES
// ================================

// Test email endpoint (for development only)
app.post('/api/test-email', async (req, res) => {
    try {
        const { email, username } = req.body;
        
        if (!email || !username) {
            return res.status(400).json({
                success: false,
                message: 'Email and username are required'
            });
        }
        
        const result = await sendWelcomeEmail(email, username);
        
        if (result.success) {
            res.json({
                success: true,
                message: 'Test email sent successfully!',
                messageId: result.messageId
            });
        } else {
            res.status(500).json({
                success: false,
                message: 'Failed to send test email',
                error: result.error
            });
        }
    } catch (error) {
        console.error('❌ Test email error:', error);
        res.status(500).json({
            success: false,
            message: 'Test email failed',
            error: error.message
        });
    }
});

// ================================

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('❌ Server error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});
// Add this middleware function near the top of your app.js file, 
// where you have your other middleware definitions

// Login requirement middleware
function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({
            success: false,
            message: 'Please log in to continue'
        });
    }
    next();
}
// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Page not found'
    });
});

// Search API endpoint
// Start server
app.listen(PORT, HOST, () => {
    console.log(`${config.app.name} server is running at http://${HOST}:${PORT}`);
});
