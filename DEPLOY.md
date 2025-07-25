# Educycle - Deploy to Render

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/mothishraghavendra/educycle)

## Quick Deploy Instructions

1. Click the "Deploy to Render" button above
2. Connect your GitHub account
3. Fork this repository or use your existing fork
4. Set up environment variables in Render dashboard
5. Create a PostgreSQL database on Render
6. Run the schema setup in your database
7. Deploy!

## Environment Variables Required

- `DATABASE_URL`: PostgreSQL connection string from Render
- `SESSION_SECRET`: Strong random secret for sessions
- `NODE_ENV`: Set to "production"
- `PORT`: Will be set automatically by Render
- `HOST`: Set to "0.0.0.0"

## Post-Deployment Setup

1. Run the PostgreSQL schema in your database
2. Test user registration and login
3. Verify product listing functionality
4. Check cart and WhatsApp integration

For detailed instructions, see the deployment guide in the repository.
