# Educycle - Student Academic Exchange Platform 🎓

**Bridging Students, Building Futures**

A modern web platform that connects senior and junior students for buying and selling academic essentials like textbooks, calculators, lab equipment, and software tools.

## 🌟 Features

### Core Functionality
- **📚 Academic Marketplace**: Buy and sell textbooks, calculators, lab equipment, and more
- **💻 Software Exchange**: Share and distribute student-developed software projects
- **👥 Student Community**: Connect with seniors and juniors from your college
- **💰 Free & Paid Listings**: Support both commercial sales and free donations
- **📱 Direct Communication**: Contact sellers directly via WhatsApp integration

### Advanced Features
- **🖼️ Image Management**: Cloudinary integration for optimized image storage
- **🔐 Secure Authentication**: BCrypt password hashing and session management
- **📧 Email Notifications**: Welcome emails and listing confirmations
- **📊 Admin Dashboard**: Comprehensive analytics and user management
- **🛒 Shopping Cart**: Add multiple items and manage purchases
- **📱 Responsive Design**: Mobile-first design for all devices

## 🚀 Tech Stack

### Backend
- **Node.js** with Express.js framework
- **MySQL** database with connection pooling
- **BCrypt** for password security
- **Express-session** with MySQL store
- **Nodemailer** for email services
- **Cloudinary** for image storage

### Frontend
- **HTML5** with semantic markup
- **CSS3** with modern flexbox/grid layouts
- **Vanilla JavaScript** for interactivity
- **Bootstrap Icons** for consistent iconography
- **Responsive Design** for all screen sizes

### External Services
- **Cloudinary** - Image storage and optimization
- **Zoho SMTP** - Email delivery service
- **WhatsApp API** - Direct seller communication

## 📁 Project Structure

```
educycle/
├── app.js                     # Main server application
├── config.js                  # Configuration management
├── emailService.js            # Email functionality
├── package.json              # Project dependencies
├── .env                      # Environment variables
├── .env.example              # Environment template
├── 
├── # Frontend Pages
├── index.html                # Landing page
├── login.html                # User authentication
├── signin.html               # User registration
├── main.html                 # Main marketplace
├── dashboard.html            # User dashboard
├── 
├── # Product Management
├── list_a_item.html          # Create new listings
├── list_a_item_new.html      # Enhanced listing form
├── list_a_item_optimized.html # Optimized listing flow
├── myitems.html              # User's listings management
├── 
├── # Product Details
├── product_detail.html       # Regular product details
├── product_detail_new.html   # Enhanced product view
├── software_detail.html      # Software-specific details
├── regular_product_detail.html # Standard product view
├── 
├── # User Management
├── Account.html              # Profile management
├── cart.html                 # Shopping cart
├── sold_items.html           # Sales history
├── contact_us.html           # Support contact
├── 
├── # Authentication
├── forgot-password.html      # Password recovery
├── resetpassword.html        # Password reset form
├── 
├── # Administration
├── admin.html                # Admin dashboard
├── admin-login.html          # Admin authentication
├── 
├── # Assets
├── images/                   # Static images
└── README.md                 # Project documentation
```

## ⚙️ Installation & Setup

### Prerequisites
- **Node.js** (v14.0.0 or higher)
- **MySQL** (v5.7 or higher)
- **npm** (v6.0.0 or higher)

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/educycle.git
cd educycle
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your configuration
nano .env
```

### 4. Configure Environment Variables
Update `.env` with your settings:

```properties
# Database Configuration
DB_HOST=localhost
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=educycle

# Server Configuration
PORT=8000
HOST=localhost

# Cloudinary (Image Storage)
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret

# Email Configuration
EMAIL_HOST=smtp.zoho.in
EMAIL_PORT=465
EMAIL_USER=your_email@domain.com
EMAIL_PASS=your_app_password

# Admin Credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=secure_password
```

### 5. Database Setup
```sql
CREATE DATABASE educycle;
-- Import database schema (contact developer for schema file)
```

### 6. Start Application
```bash
# Development mode
npm run dev

# Production mode
npm start
```

## 🐳 Docker Deployment

### Using Docker Compose (Recommended)
```bash
# Deploy with one command
./deploy.sh  # Linux/Mac
deploy.bat   # Windows

# Or manually
docker-compose up -d --build
```

### Services Included
- **Application Server** (Node.js)
- **MySQL Database** with initialization
- **Redis** for session storage
- **Nginx** reverse proxy
- **Automatic health checks**
- **Volume persistence**

### Docker Environment
The project includes complete Docker configuration:
- `Dockerfile` - Application container
- `docker-compose.yml` - Multi-service orchestration
- `database/init.sql` - Database schema
- `nginx/nginx.conf` - Reverse proxy configuration

## 🔧 Available Scripts

```bash
npm start          # Start production server
npm run dev        # Start development server with nodemon
npm run setup      # Run initial setup
npm run validate-env # Validate environment configuration
npm run db-check   # Test database connection
npm run clean      # Clean log files

# Docker commands
npm run docker:build    # Build Docker containers
npm run docker:up      # Start Docker services
npm run docker:down    # Stop Docker services
npm run docker:logs    # View service logs
```

## 🏗️ Key Components

### Authentication System
- Session-based authentication with MySQL store
- BCrypt password hashing (12 rounds)
- Email verification with OTP
- Password reset via email OTP
- Admin panel with separate authentication

### Product Management
- **Regular Products**: Textbooks, calculators, lab equipment
- **Software Products**: Student-developed applications with:
  - Download links and demo videos
  - GitHub integration
  - Technical specifications
  - Feature listings
  - System requirements

### Image Handling
- Cloudinary integration for optimized storage
- Multiple image upload support
- Automatic image optimization
- Responsive image delivery

### Email System
- Welcome emails for new users
- Email verification during registration
- Product listing notifications
- Password reset functionality
- SMTP configuration via Zoho

### Admin Dashboard
- User management and analytics
- Product moderation with charts
- Sales tracking and reporting
- Monthly/yearly analytics
- System performance monitoring

## 🌐 API Endpoints

### Authentication
- `POST /login` - User login
- `POST /signin` - User registration
- `POST /logout` - User logout
- `POST /send-otp` - Send email verification OTP
- `POST /verify-otp` - Verify email OTP
- `POST /admin-login` - Admin authentication

### Products
- `GET /api/products` - List all products
- `POST /api/products` - Create new product
- `GET /api/product/:id` - Get product details
- `PUT /api/product/:id` - Update product
- `DELETE /api/product/:id` - Delete product

### Software
- `GET /api/software/:id` - Get software details
- `POST /api/software` - Create software listing
- `POST /api/software/:id/download` - Record download

### User Management
- `GET /api/profile` - Get user profile
- `PUT /api/profile` - Update user profile
- `GET /api/my-products` - Get user's listings

### Admin API
- `GET /admin/api/dashboard-stats` - Dashboard statistics
- `GET /admin/api/products` - Product management
- `GET /admin/api/product-analytics` - Product analytics
- `GET /admin/api/users` - User management
- `GET /admin/api/orders` - Order management
- `GET /admin/api/analytics` - Sales analytics with filters

## 🎨 UI/UX Features

### Design Philosophy
- **Student-Centric**: Designed specifically for student needs
- **Mobile-First**: Responsive design for all devices
- **Intuitive Navigation**: Clear, simple user flows
- **Modern Aesthetics**: Clean, professional appearance

### Key Pages
- **Landing Page**: Marketing and feature showcase
- **Main Marketplace**: Product browsing and search
- **Product Details**: Detailed product information with verification
- **Listing Creation**: Easy product listing flow
- **User Dashboard**: Personal account management
- **Admin Panel**: Advanced analytics with charts

### Email Verification Flow
1. User enters email during registration
2. Click "Verify" button to send OTP
3. Enter 6-digit OTP received via email
4. Email verified with visual confirmation
5. Registration enabled after verification

## 🔒 Security Features

### Data Protection
- Environment variable configuration
- SQL injection prevention with parameterized queries
- Session security with HTTPOnly cookies
- Password hashing with BCrypt
- File upload validation and sanitization
- Email verification to prevent fake accounts

### Admin Security
- Separate admin authentication system
- Role-based access control
- Secure admin panel with analytics
- Rate limiting on authentication endpoints

## 📧 Email Integration

The platform uses email services for:
- **Welcome Emails**: Sent to new users with onboarding information
- **Email Verification**: OTP-based email verification during registration
- **Product Notifications**: Listing confirmations and updates
- **Password Recovery**: Secure OTP-based password reset

### Email Configuration
```javascript
// Zoho SMTP Configuration
EMAIL_HOST=smtp.zoho.in
EMAIL_PORT=465
EMAIL_SECURE=true
EMAIL_USER=sahara@educycle.me
EMAIL_PASS=your_app_password
```

## 🌍 Deployment Options

### Traditional Deployment
1. **Environment**: Set `NODE_ENV=production`
2. **Database**: Use production MySQL instance
3. **SSL**: Configure HTTPS for secure communication
4. **Sessions**: Use secure session configuration
5. **Monitoring**: Implement logging and error tracking

### Docker Deployment (Recommended)
```bash
# Quick deployment
docker-compose up -d --build

# Access services
# App: http://localhost:8000
# Admin: http://localhost:8000/admin
# Database: localhost:3306
```

### Recommended Hosting
- **Containerized**: Docker on DigitalOcean, AWS ECS, or Google Cloud Run
- **Traditional**: Heroku, Vercel, or Netlify
- **Database**: MySQL on cloud (AWS RDS, Google Cloud SQL)
- **Images**: Cloudinary (already configured)
- **Domain**: Custom domain with SSL certificate

## 📊 Analytics & Monitoring

### Admin Dashboard Features
- **Product Analytics**: 
  - Pie chart for product type distribution
  - Bar chart for product availability status
- **Sales Analytics**:
  - Monthly/yearly sales filtering
  - Revenue trends with line charts
  - Top-selling products
  - Average order values

### Health Monitoring
- Application health checks
- Database connection monitoring
- Service uptime tracking
- Error logging and reporting

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Development Guidelines
- Follow existing code style and conventions
- Add tests for new features
- Update documentation for API changes
- Ensure Docker compatibility

## 🚨 Troubleshooting

### Common Issues
```bash
# Database connection issues
npm run db-check

# Environment variable problems
npm run validate-env

# Docker issues
docker-compose logs -f [service_name]

# Application logs
tail -f logs/app.log
```

### Docker Troubleshooting
```bash
# Check service status
docker-compose ps

# View service logs
docker-compose logs -f app
docker-compose logs -f mysql

# Restart services
docker-compose restart

# Clean restart
docker-compose down && docker-compose up -d --build
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Author

**Mothish K Raghavendra**
- Email: [sahara@educycle.me](mailto:sahara@educycle.me)
- GitHub: [@yourusername](https://github.com/yourusername)

## 🎯 Mission Statement

*"Bridging Students, Building Futures"* - Educycle aims to create a sustainable academic ecosystem where students can easily access educational materials while contributing to a circular economy that benefits the entire student community.

## 🔮 Future Enhancements

- [ ] Mobile application (React Native/Flutter)
- [ ] Payment gateway integration
- [ ] Advanced search with filters
- [ ] Real-time chat system
- [ ] AI-powered product recommendations
- [ ] Integration with college management systems
- [ ] Gamification and student rewards program
- [ ] Multi-language support

---

**Built with ❤️ for students, by students**

*Ready to deploy? Run