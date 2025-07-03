#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

console.log('🚀 Setting up Educycle...\n');

// Check if .env exists
if (!fs.existsSync('.env')) {
    console.log('📝 Creating .env file from template...');
    fs.copyFileSync('.env.example', '.env');
    console.log('✅ .env file created successfully!');
    console.log('⚠️  Please edit .env file and add your database password and session secret.\n');
} else {
    console.log('✅ .env file already exists.\n');
}

// Install dependencies
console.log('📦 Installing dependencies...');
try {
    execSync('npm install', { stdio: 'inherit' });
    console.log('✅ Dependencies installed successfully!\n');
} catch (error) {
    console.error('❌ Failed to install dependencies:', error.message);
    process.exit(1);
}

// Validate configuration
console.log('🔍 Validating configuration...');
try {
    const { validateConfig } = require('./config');
    validateConfig();
    console.log('✅ Configuration is valid!\n');
} catch (error) {
    console.log('⚠️  Configuration validation failed:');
    console.log(error.message);
    console.log('\n💡 Please check your .env file and ensure all required variables are set.\n');
}

console.log('🎉 Setup complete!');
console.log('');
console.log('Next steps:');
console.log('1. Edit .env file with your database credentials');
console.log('2. Make sure MySQL server is running');
console.log('3. Run: npm start');
console.log('4. Open: http://localhost:8080');
console.log('');
console.log('For development with auto-reload, run: npm run dev');
