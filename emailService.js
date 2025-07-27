const nodemailer = require('nodemailer');
const { config } = require('./config');

// Create transporter using Zoho SMTP from environment variables  
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'smtp.zoho.in',
    port: parseInt(process.env.EMAIL_PORT) || 465,
    secure: process.env.EMAIL_SECURE === 'true' || true, // true for port 465
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
});

// Verify transporter configuration
transporter.verify((error, success) => {
    if (error) {
        console.error('❌ Email service configuration error:', error);
    } else {
        console.log('✅ Email service is ready to send messages');
    }
});

// Send welcome email to new users
async function sendWelcomeEmail(userEmail, userName) {
    const mailOptions = {
        from: `"EduCycle Team" <${process.env.EMAIL_USER}>`,
        to: userEmail,
        subject: '🎉 Welcome to EduCycle - Your Educational Marketplace!',
        html: `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Welcome to EduCycle</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: #f4f4f4;
                    }
                    .email-container {
                        background-color: white;
                        padding: 30px;
                        border-radius: 10px;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    }
                    .header {
                        text-align: center;
                        margin-bottom: 30px;
                    }
                    .logo {
                        font-size: 28px;
                        font-weight: bold;
                        color: #1e3a8a;
                        margin-bottom: 10px;
                    }
                    .welcome-text {
                        font-size: 18px;
                        color: #52ab98;
                        margin-bottom: 20px;
                    }
                    .content {
                        margin-bottom: 30px;
                    }
                    .feature-list {
                        background-color: #f8f9fa;
                        padding: 20px;
                        border-radius: 8px;
                        margin: 20px 0;
                    }
                    .feature-list ul {
                        margin: 0;
                        padding-left: 20px;
                    }
                    .feature-list li {
                        margin-bottom: 8px;
                        color: #555;
                    }
                    .cta-button {
                        display: inline-block;
                        background-color: #52ab98;
                        color: white;
                        padding: 12px 25px;
                        text-decoration: none;
                        border-radius: 5px;
                        font-weight: bold;
                        margin: 10px 0;
                    }
                    .footer {
                        margin-top: 30px;
                        padding-top: 20px;
                        border-top: 1px solid #ddd;
                        text-align: center;
                        font-size: 14px;
                        color: #666;
                    }
                    .social-links {
                        margin: 15px 0;
                    }
                    .social-links a {
                        margin: 0 10px;
                        color: #52ab98;
                        text-decoration: none;
                    }
                </style>
            </head>
            <body>
                <div class="email-container">
                    <div class="header">
                        <div class="logo">📚 EduCycle</div>
                        <div class="welcome-text">Welcome to Your Educational Marketplace!</div>
                    </div>
                    
                    <div class="content">
                        <h2>Hello ${userName}! 👋</h2>
                        
                        <p>We're thrilled to have you join the EduCycle community! Your account has been successfully created, and you're now part of a sustainable educational ecosystem.</p>
                        
                        <div class="feature-list">
                            <h3>🌟 What you can do with EduCycle:</h3>
                            <ul>
                                <li><strong>Buy & Sell:</strong> Find affordable textbooks, calculators, and lab equipment</li>
                                <li><strong>Sustainable Learning:</strong> Give educational items a second life</li>
                                <li><strong>Community Driven:</strong> Connect with fellow students and educators</li>
                                <li><strong>Easy Transactions:</strong> Secure and simple buying/selling process</li>
                                <li><strong>Local Marketplace:</strong> Find items in your area</li>
                            </ul>
                        </div>
                        
                        <p>Ready to start your sustainable education journey? Here are your next steps:</p>
                        
                        <ol>
                            <li><strong>Complete your profile</strong> - Add your location and preferences</li>
                            <li><strong>Browse items</strong> - Check out what's available in your area</li>
                            <li><strong>List your items</strong> - Sell books you no longer need</li>
                            <li><strong>Start saving</strong> - Find great deals on educational materials</li>
                        </ol>
                        
                        <center>
                            <a href="http://localhost:8080/dashboard" class="cta-button">🚀 Get Started Now</a>
                        </center>
                    </div>
                    
                    <div class="footer">
                        <p><strong>Need help?</strong> We're here for you!</p>
                        <div class="social-links">
                            <a href="mailto:${process.env.EMAIL_USER}">📧 Email Support</a> |
                            <a href="http://localhost:8080/contact">💬 Contact Us</a>
                        </div>
                        <p>Thank you for choosing EduCycle - Together, we're making education more accessible and sustainable! 🌱</p>
                        <p style="font-size: 12px; color: #999;">
                            This email was sent to ${userEmail}. If you didn't create an account with EduCycle, please ignore this email.
                        </p>
                    </div>
                </div>
            </body>
            </html>
        `,
        text: `
            Welcome to EduCycle, ${userName}!
            
            We're thrilled to have you join our educational marketplace community! Your account has been successfully created.
            
            What you can do with EduCycle:
            • Buy & Sell educational items like textbooks, calculators, and lab equipment
            • Connect with fellow students and educators in your area
            • Contribute to sustainable education by giving items a second life
            • Save money on educational materials
            
            Next steps:
            1. Complete your profile with location and preferences
            2. Browse available items in your area
            3. List any educational items you want to sell
            4. Start saving on educational materials!
            
            Visit your dashboard: http://localhost:8080/dashboard
            
            Need help? Contact us at ${process.env.EMAIL_USER}
            
            Thank you for choosing EduCycle - Together, we're making education more accessible and sustainable!
            
            Best regards,
            The EduCycle Team
        `
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('✅ Welcome email sent successfully to:', userEmail);
        console.log('📧 Message ID:', info.messageId);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error('❌ Error sending welcome email to:', userEmail, error);
        return { success: false, error: error.message };
    }
}

// Send notification email for new product listing
async function sendProductListingNotification(userEmail, userName, productName) {
    const mailOptions = {
        from: `"EduCycle Team" <${process.env.EMAIL_USER}>`,
        to: userEmail,
        subject: '✅ Your item has been listed on EduCycle!',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #1e3a8a;">📚 EduCycle</h2>
                <h3>Great news, ${userName}! 🎉</h3>
                <p>Your item "<strong>${productName}</strong>" has been successfully listed on EduCycle marketplace!</p>
                <p>Your listing is now visible to potential buyers in your area. We'll notify you when someone shows interest in your item.</p>
                <p style="margin-top: 20px;">
                    <a href="http://localhost:8080/dashboard" style="background-color: #52ab98; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Your Listings</a>
                </p>
                <p style="margin-top: 30px; font-size: 14px; color: #666;">
                    Best regards,<br>
                    The EduCycle Team
                </p>
            </div>
        `,
        text: `
            Great news, ${userName}!
            
            Your item "${productName}" has been successfully listed on EduCycle marketplace!
            
            Your listing is now visible to potential buyers in your area. We'll notify you when someone shows interest in your item.
            
            View your listings: http://localhost:8080/dashboard
            
            Best regards,
            The EduCycle Team
        `
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('✅ Product listing notification sent to:', userEmail);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error('❌ Error sending product listing notification:', error);
        return { success: false, error: error.message };
    }
}

// Send OTP email for password reset
async function sendPasswordResetOTP(userEmail, userName, otp) {
    const mailOptions = {
        from: `"EduCycle Team" <${process.env.EMAIL_USER}>`,
        to: userEmail,
        subject: '🔐 Password Reset OTP - EduCycle',
        html: `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Password Reset OTP</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: #f4f4f4;
                    }
                    .email-container {
                        background-color: white;
                        padding: 30px;
                        border-radius: 10px;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    }
                    .header {
                        text-align: center;
                        margin-bottom: 30px;
                    }
                    .logo {
                        font-size: 28px;
                        font-weight: bold;
                        color: #1e3a8a;
                        margin-bottom: 10px;
                    }
                    .otp-box {
                        background-color: #f8f9fa;
                        border: 2px solid #52ab98;
                        border-radius: 10px;
                        padding: 20px;
                        text-align: center;
                        margin: 20px 0;
                    }
                    .otp-code {
                        font-size: 32px;
                        font-weight: bold;
                        color: #52ab98;
                        letter-spacing: 5px;
                        margin: 10px 0;
                    }
                    .warning-box {
                        background-color: #fff3cd;
                        border: 1px solid #ffeaa7;
                        border-radius: 6px;
                        padding: 15px;
                        margin: 20px 0;
                    }
                    .footer {
                        margin-top: 30px;
                        padding-top: 20px;
                        border-top: 1px solid #ddd;
                        text-align: center;
                        font-size: 14px;
                        color: #666;
                    }
                </style>
            </head>
            <body>
                <div class="email-container">
                    <div class="header">
                        <div class="logo">🔐 EduCycle</div>
                        <h2>Password Reset Request</h2>
                    </div>
                    
                    <p>Hello ${userName},</p>
                    
                    <p>We received a request to reset your password for your EduCycle account. Please use the following One-Time Password (OTP) to proceed:</p>
                    
                    <div class="otp-box">
                        <p style="margin: 0; font-size: 18px; color: #666;">Your OTP Code:</p>
                        <div class="otp-code">${otp}</div>
                        <p style="margin: 0; font-size: 14px; color: #666;">This code is valid for 10 minutes</p>
                    </div>
                    
                    <div class="warning-box">
                        <p style="margin: 0;"><strong>⚠️ Security Notice:</strong></p>
                        <ul style="margin: 10px 0; padding-left: 20px;">
                            <li>This OTP will expire in <strong>10 minutes</strong></li>
                            <li>Do not share this code with anyone</li>
                            <li>If you didn't request this reset, please ignore this email</li>
                            <li>Your password will remain unchanged until you complete the reset process</li>
                        </ul>
                    </div>
                    
                    <p>If you're having trouble with the password reset process, please contact our support team at <a href="mailto:${process.env.EMAIL_USER}">${process.env.EMAIL_USER}</a></p>
                    
                    <div class="footer">
                        <p><strong>Need help?</strong> We're here for you!</p>
                        <p>Contact us: <a href="mailto:${process.env.EMAIL_USER}">${process.env.EMAIL_USER}</a></p>
                        <p style="font-size: 12px; color: #999;">
                            This email was sent to ${userEmail}. If you didn't request a password reset, please ignore this email.
                        </p>
                    </div>
                </div>
            </body>
            </html>
        `,
        text: `
            Password Reset Request - EduCycle
            
            Hello ${userName},
            
            We received a request to reset your password for your EduCycle account.
            
            Your OTP Code: ${otp}
            
            This code is valid for 10 minutes.
            
            Security Notice:
            - This OTP will expire in 10 minutes
            - Do not share this code with anyone
            - If you didn't request this reset, please ignore this email
            - Your password will remain unchanged until you complete the reset process
            
            If you're having trouble, contact us at ${process.env.EMAIL_USER}
            
            Best regards,
            The EduCycle Team
        `
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('✅ Password reset OTP sent to:', userEmail);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error('❌ Error sending password reset OTP:', error);
        return { success: false, error: error.message };
    }
}

module.exports = {
    sendWelcomeEmail,
    sendProductListingNotification,
    sendPasswordResetOTP
};
