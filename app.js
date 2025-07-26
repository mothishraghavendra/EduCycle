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

const app = express();

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
                image1 LONGBLOB,
                image2 LONGBLOB,
                image3 LONGBLOB,
                category VARCHAR(100),
                condition_item VARCHAR(100),
                description TEXT,
                price DECIMAL(10, 2) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `;
        await promisePool.execute(createTableQuery);
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

// Initialize database
createUsersTable();
createProductsTable();
createSoldItemsTable();
createCartTable();

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
// PRODUCT API ENDPOINTS
// =============================================================

// Add new product
app.post('/api/add-product', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in to add products' });
    }

    const { name, description, price, category, condition, image1, image2, image3 } = req.body;
    const userId = req.session.userId;

    // Function to convert base64 to binary buffer
    function convertBase64ToBuffer(base64String) {
        if (!base64String) return null;
        try {
            // Remove data URL prefix if present (e.g., "data:image/jpeg;base64,")
            const base64Data = base64String.replace(/^data:image\/\w+;base64,/, '');
            return Buffer.from(base64Data, 'base64');
        } catch (error) {
            console.error('Error converting base64 to buffer:', error);
            return null;
        }
    }

    // Convert base64 images to binary buffers
    const imageBuffer1 = convertBase64ToBuffer(image1);
    const imageBuffer2 = convertBase64ToBuffer(image2);
    const imageBuffer3 = convertBase64ToBuffer(image3);

    // Debug: Log received data
    console.log('Received product data:', {
        name,
        description: description ? description.substring(0, 50) + '...' : '',
        price,
        category,
        condition,
        hasImage1: !!imageBuffer1,
        hasImage2: !!imageBuffer2,
        hasImage3: !!imageBuffer3,
        userId
    });

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
        const [result] = await promisePool.execute(
            'INSERT INTO products (user_id, name, description, price, category, condition_item, image1, image2, image3) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [userId, name, description || '', finalPrice, category, condition, imageBuffer1, imageBuffer2, imageBuffer3]
        );

        console.log(`✅ New product added: ${name} by user ID ${userId}`);

        res.json({
            success: true,
            message: 'Product added successfully!',
            productId: result.insertId
        });

    } catch (error) {
        console.error('❌ Add product error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add product. Please try again.'
        });
    }
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

        // Convert BLOB images to base64 for frontend
        const productsWithImages = products.map(product => ({
            ...product,
            image1: product.image1 ? `data:image/jpeg;base64,${product.image1.toString('base64')}` : null,
            image2: product.image2 ? `data:image/jpeg;base64,${product.image2.toString('base64')}` : null,
            image3: product.image3 ? `data:image/jpeg;base64,${product.image3.toString('base64')}` : null
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

// Get user's own products
app.get('/api/my-products', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    try {
        const [products] = await promisePool.execute(`
            SELECT 
                product_id,
                name,
                description,
                price,
                category,
                condition_item,
                image1,
                image2,
                image3,
                created_at
            FROM products 
            WHERE user_id = ?
            ORDER BY created_at DESC
        `, [req.session.userId]);

        // Convert BLOB images to base64 for frontend
        const productsWithImages = products.map(product => ({
            ...product,
            image1: product.image1 ? `data:image/jpeg;base64,${product.image1.toString('base64')}` : null,
            image2: product.image2 ? `data:image/jpeg;base64,${product.image2.toString('base64')}` : null,
            image3: product.image3 ? `data:image/jpeg;base64,${product.image3.toString('base64')}` : null
        }));

        res.json({
            success: true,
            products: productsWithImages,
            count: productsWithImages.length
        });

    } catch (error) {
        console.error('❌ Get my products error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch your products'
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
        const [cartItems] = await promisePool.execute(`
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
                c.product_image,
                c.quantity,
                c.added_at,
                u.phone as seller_phone
            FROM cart c
            LEFT JOIN users u ON c.seller_id = u.id
            WHERE c.user_id = ?
            ORDER BY c.added_at DESC
        `, [req.session.userId]);

        // Convert BLOB image to base64 for frontend
        const cartItemsWithImages = cartItems.map(item => ({
            ...item,
            product_image: item.product_image ? `data:image/jpeg;base64,${item.product_image.toString('base64')}` : null,
        }));

        // Calculate total
        const total = cartItems.reduce((sum, item) => sum + (parseFloat(item.product_price) * item.quantity), 0);

        res.json({
            success: true,
            cartItems: cartItemsWithImages,
            count: cartItems.length,
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
        const [result] = await promisePool.execute(
            'SELECT COUNT(*) as count FROM cart WHERE user_id = ?',
            [req.session.userId]
        );

        res.json({
            success: true,
            count: result[0].count
        });
    } catch (error) {
        console.error('❌ Get cart count error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch cart count'
        });
    }
});

// Add item to cart
app.post('/api/cart/add', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }

    const { productId } = req.body;

    try {
        // First, get the product details and seller info
        const [products] = await promisePool.execute(`
            SELECT 
                p.product_id,
                p.name,
                p.price,
                p.category,
                p.condition_item,
                p.description,
                p.image1,
                p.user_id as seller_id,
                u.username as seller_name
            FROM products p
            JOIN users u ON p.user_id = u.id
            WHERE p.product_id = ?
        `, [productId]);

        if (products.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Product not found'
            });
        }

        const product = products[0];

        // Check if user is trying to add their own product
        if (product.seller_id === req.session.userId) {
            return res.status(400).json({
                success: false,
                message: 'You cannot add your own product to cart'
            });
        }

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
            // Add new item to cart
            await promisePool.execute(`
                INSERT INTO cart (
                    user_id, product_id, product_name, product_price,
                    product_category, product_condition, product_description,
                    seller_id, seller_name, product_image, quantity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
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
                product.image1
            ]);
        }

        res.json({
            success: true,
            message: 'Item added to cart successfully'
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

        // Remove item from cart
        await promisePool.execute(
            'DELETE FROM cart WHERE cart_id = ?',
            [cartId]
        );

        res.json({
            success: true,
            message: 'Item removed from cart successfully'
        });

    } catch (error) {
        console.error('❌ Remove from cart error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to remove item from cart'
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
app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
    try {
        const [
            [totalUsersResult],
            [totalProductsResult],
            [productsSoldResult],
            [totalRevenueResult],
            [freeDonationsResult],
            [activeTodayResult]
        ] = await Promise.all([
            promisePool.execute('SELECT COUNT(*) as count FROM users'),
            promisePool.execute('SELECT COUNT(*) as count FROM products'),
            promisePool.execute('SELECT COUNT(*) as count FROM sold_items'),
            promisePool.execute('SELECT COALESCE(SUM(price), 0) as total FROM sold_items'),
            promisePool.execute('SELECT COUNT(*) as count FROM products WHERE price = 0'),
            promisePool.execute(`
                SELECT COUNT(DISTINCT user_id) as count 
                FROM products 
                WHERE DATE(created_at) = CURDATE()
            `)
        ]);

        // Get recent activity
        const [recentActivity] = await promisePool.execute(`
            SELECT 
                CONCAT('User ', u.username, ' listed ', p.name) as message,
                p.created_at as timestamp
            FROM products p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
            LIMIT 10
        `);

        res.json({
            success: true,
            data: {
                totalUsers: totalUsersResult[0].count,
                totalProducts: totalProductsResult[0].count,
                productsSold: productsSoldResult[0].count,
                totalRevenue: totalRevenueResult[0].total,
                freeDonations: freeDonationsResult[0].count,
                activeToday: activeTodayResult[0].count,
                recentActivity: recentActivity
            }
        });

    } catch (error) {
        console.error('❌ Admin dashboard error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load dashboard data'
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
        const [products] = await promisePool.execute(`
            SELECT 
                p.*,
                u.username,
                CASE WHEN s.original_product_id IS NOT NULL THEN 1 ELSE 0 END as is_sold
            FROM products p
            JOIN users u ON p.user_id = u.id
            LEFT JOIN sold_items s ON p.product_id = s.original_product_id
            ORDER BY p.created_at DESC
        `);

        // Convert LONGBLOB images to base64 for display
        const productsWithImages = products.map(product => {
            const productCopy = { ...product };
            
            // Convert image1 LONGBLOB to base64 data URL
            if (product.image1) {
                const base64Image = Buffer.from(product.image1).toString('base64');
                productCopy.image1 = `data:image/jpeg;base64,${base64Image}`;
            }
            
            // Remove LONGBLOB data from other image fields to avoid sending large data
            delete productCopy.image2;
            delete productCopy.image3;
            
            return productCopy;
        });

        res.json({
            success: true,
            products: productsWithImages
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
            'DELETE FROM sold_items WHERE product_id = ?',
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
            
            // Delete from sold_items (both as seller and buyer)
            await connection.execute('DELETE FROM sold_items WHERE seller_id = ? OR buyer_id = ?', [userId, userId]);
            
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

// ================================
// END ADMIN PANEL ROUTES
// ================================

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('❌ Server error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Page not found'
    });
});

// Start server
app.listen(PORT, HOST, () => {
    console.log(`${config.app.name} server is running at http://${HOST}:${PORT}`);
});
