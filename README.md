# Educycle - Student Academic Item Exchange Platform

A modern web application for students to buy and sell academic items like textbooks, calculators, lab equipment, and more.

## Features
- 🔐 Secure user authentication with bcrypt encryption
- 📱 Responsive design for all devices
- 🛒 Advanced cart system with user-specific data
- 📞 WhatsApp contact integration for seller communication
- 🔍 Category-based product filtering
- 📊 Personal dashboard with sales tracking
- 🖼️ Image upload support for products
- ✅ Mark items as sold functionality

## Prerequisites
1. **Node.js** (v14 or higher) - Download from https://nodejs.org/
2. **MySQL Server** (v5.7 or higher)
3. **Git** (optional) - For version control

## Setup Instructions

### 1. Clone the Repository
```bash
git clone <repository-url>
cd educycle
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Environment Configuration
1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit the `.env` file with your configuration:
   ```env
   # Database Configuration
   DB_HOST=localhost
   DB_USER=root
   DB_PASSWORD="your_database_password"
   DB_NAME=educycle
   
   # Session Configuration
   SESSION_SECRET="your_strong_session_secret_here"
   
   # Server Configuration
   PORT=8080
   HOST=localhost
   ```

   **Important:** 
   - Replace `your_database_password` with your actual MySQL password
   - Use quotes around passwords containing special characters (e.g., `"#Mothish@123"`)
   - Generate a strong random string for `SESSION_SECRET` (at least 32 characters)
   - Use quotes around the session secret if it contains special characters

### 4. Database Setup
1. Start your MySQL server
2. Create the database:
   ```sql
   CREATE DATABASE IF NOT EXISTS educycle;
   ```

   **Note:** The application will automatically create all required tables on first startup.

### 5. Start the Application

For development (with auto-restart):
```bash
npm run dev
```

For production:
```bash
npm start
```

### 6. Access the Application
Open your browser and navigate to: http://localhost:8080

## Configuration Options

### Environment Variables
| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DB_HOST` | Database host | localhost | No |
| `DB_USER` | Database username | root | No |
| `DB_PASSWORD` | Database password | - | **Yes** |
| `DB_NAME` | Database name | educycle | No |
| `SESSION_SECRET` | Session encryption key | - | **Yes** |
| `PORT` | Server port | 8080 | No |
| `HOST` | Server host | localhost | No |
| `NODE_ENV` | Environment mode | development | No |

### Security Notes
- Never commit your `.env` file to version control
- Use strong passwords for both database and session secret
- In production, set `NODE_ENV=production` for enhanced security
- Consider using HTTPS in production environments

## Project Structure
```
educycle/
├── app.js              # Main server file with all API endpoints
├── config.js           # Configuration management
├── package.json        # Dependencies and scripts
├── .env.example        # Environment variables template
├── .gitignore          # Git ignore rules
├── README.md           # This file
├── index.html          # Landing page
├── login.html          # User login
├── signin.html         # User registration
├── dashboard.html      # User dashboard with iframe navigation
├── main.html           # Product browsing and category filtering
├── Account.html        # User profile management
├── cart.html           # Shopping cart with WhatsApp integration
├── myitems.html        # User's listed products
├── list_a_item.html    # Add new product form
├── contact_us.html     # Contact/support page
└── images/             # Static image assets
```
├── main.html           # Dashboard content
├── myitems.html        # User's items
├── list_a_item.html    # Add new item
└── images/             # Static images
    ├── logo.png
    └── calculus.jpg
```

## API Endpoints

### Authentication
- `POST /signin` - User registration
- `POST /login` - User login
- `POST /logout` - User logout
- `GET /api/auth-status` - Check authentication status

### User Profile
- `GET /api/profile` - Get user profile data
- `PUT /api/profile` - Update user profile

### Products
- `GET /api/products` - Get all products (excluding user's own)
- `GET /api/my-products` - Get user's listed products
- `POST /api/add-product` - Add a new product
- `DELETE /api/products/:productId` - Delete a product
- `POST /api/products/:productId/mark-sold` - Mark product as sold

### Cart
- `GET /api/cart` - Get user's cart items
- `POST /api/cart/add` - Add item to cart
- `PUT /api/cart/:cartId` - Update cart item quantity
- `DELETE /api/cart/:cartId` - Remove item from cart

### Sold Items
- `GET /api/my-sold-items` - Get user's sold items history

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone VARCHAR(20) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    location VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

### Products Table
```sql
CREATE TABLE products (
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
);
```

### Cart Table
```sql
CREATE TABLE cart (
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
);
```

### Sold Items Table
```sql
CREATE TABLE sold_items (
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
);
```

## Deployment

### Production Setup
1. Set environment to production:
   ```env
   NODE_ENV=production
   ```

2. Use a process manager like PM2:
   ```bash
   npm install -g pm2
   pm2 start app.js --name "educycle"
   pm2 startup
   pm2 save
   ```

3. Configure reverse proxy (Nginx example):
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://localhost:8080;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
           proxy_cache_bypass $http_upgrade;
       }
   }
   ```

### Security Recommendations
- Use HTTPS in production
- Implement rate limiting
- Use strong database passwords
- Regularly update dependencies
- Enable MySQL security features
- Consider using a CDN for static assets

## Troubleshooting

### Common Issues

1. **Database Connection Error**
   - Check if MySQL server is running
   - Verify database credentials in `.env`
   - Ensure database exists

2. **Session Issues**
   - Verify `SESSION_SECRET` is set
   - Check session store configuration
   - Clear browser cookies if needed

3. **Port Already in Use**
   - Change `PORT` in `.env` file
   - Kill existing process: `npx kill-port 8080`

4. **Missing Dependencies**
   - Run `npm install` to install all dependencies
   - Check Node.js version compatibility

### Logs
- Application logs are printed to console
- Use `console.log` statements for debugging
- Consider using a logging library like Winston for production

## Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License
This project is licensed under the MIT License.

## Support
For support or questions, please contact [your-email@example.com] or create an issue in the repository.
