<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# KeyPouch Directory

A secure secret management system with role-based access control, team collaboration, and comprehensive audit logging.

## Features

- 🔐 **Secure Secret Management**: Store and manage passwords, API keys, and credentials
- 👥 **Role-Based Access Control**: Admin, Full Access, Modify, and View roles
- 🏢 **Team Collaboration**: Team-tagged secrets shared across team members
- 📊 **Audit Logging**: Comprehensive activity tracking and monitoring
- 🔑 **Multi-Dimensional Access Rules**: Fine-grained access control by type, environment, and service domain
- 🛡️ **Security Features**: Password reset, MFA support, session management

## Architecture

- **Backend**: Node.js with Express and PostgreSQL
- **Frontend**: React with TypeScript and Tailwind CSS
- **Database**: PostgreSQL with comprehensive schema
- **Authentication**: JWT-based with session versioning

## Prerequisites

- Node.js (v16 or higher)
- PostgreSQL (v12 or higher)
- Docker and Docker Compose (for containerized deployment)

## Quick Start

### Using Docker Compose (Recommended)

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd keypouch-directory
   ```

2. Start the application:
   ```bash
   docker-compose up -d
   ```

3. Access the application:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:5001
   - Default admin credentials: `admin` / `admin`

### Manual Setup

1. **Install dependencies**:
   ```bash
   # Backend
   cd backend
   npm install

   # Frontend
   cd ../web
   npm install
   ```

2. **Set up the database**:
   ```bash
   # Create PostgreSQL database
   createdb keypouch

   # Run schema initialization
   psql -d keypouch -f app/init.sql
   ```

3. **Configure environment variables**:
   ```bash
   # Backend environment
   cp backend/.env.example backend/.env
   # Edit backend/.env with your configuration

   # Frontend environment
   cp web/.env.example web/.env.local
   # Edit web/.env.local with your configuration
   ```

4. **Start the services**:
   ```bash
   # Backend (in terminal 1)
   cd backend
   npm run dev

   # Frontend (in terminal 2)
   cd web
   npm run dev
   ```

## Configuration

### Backend Environment Variables

Create `backend/.env` with the following variables:

```env
# Database
DATABASE_URL=postgresql://admin:password@localhost:5432/keypouch
DB_HOST=localhost
DB_PORT=5432
DB_NAME=keypouch
DB_USER=admin
DB_PASSWORD=your_secure_password

# JWT
JWT_SECRET=your_very_long_random_secret_key_here
JWT_EXPIRES_IN=24h

# Server
PORT=5001
NODE_ENV=production

# CORS
FRONTEND_URL=http://localhost:3000
```

### Frontend Environment Variables

Create `web/.env.local` with the following variables:

```env
REACT_APP_API_URL=http://localhost:5001/api
REACT_APP_APP_NAME=KeyPouch Directory
```

## Deployment

### Docker Production Deployment

1. **Prepare production environment**:
   ```bash
   # Create production environment file
   cp docker-compose.yml docker-compose.prod.yml
   # Edit docker-compose.prod.yml for production settings
   ```

2. **Build and deploy**:
   ```bash
   docker-compose -f docker-compose.prod.yml up -d --build
   ```

3. **Secure the deployment**:
   - Change default passwords
   - Use environment-specific secrets
   - Configure reverse proxy (nginx/Apache)
   - Set up SSL certificates

### Cloud Deployment Options

#### AWS ECS/Fargate

1. Build and push Docker images to ECR
2. Create ECS task definition
3. Deploy using ECS service
4. Configure Application Load Balancer
5. Set up RDS PostgreSQL instance

#### Google Cloud Run

1. Build and push images to Google Container Registry
2. Deploy to Cloud Run
3. Configure Cloud SQL PostgreSQL
4. Set up IAM and secrets management

#### Azure Container Instances

1. Push images to Azure Container Registry
2. Deploy to Container Instances
3. Configure Azure Database for PostgreSQL
4. Set up Azure Key Vault for secrets

### Production Security Checklist

- [ ] Change all default passwords
- [ ] Use strong, randomly generated secrets
- [ ] Enable HTTPS with valid SSL certificates
- [ ] Configure firewall rules
- [ ] Set up database backups
- [ ] Enable audit logging
- [ ] Configure monitoring and alerting
- [ ] Implement rate limiting
- [ ] Set up log rotation
- [ ] Regular security updates

## Development

### Running Tests

```bash
# Backend tests
cd backend
npm test

# Frontend tests
cd web
npm test
```

### Code Style

The project uses ESLint and Prettier for code formatting:

```bash
# Lint and fix
npm run lint:fix

# Format code
npm run format
```

## API Documentation

### Authentication Endpoints

- `POST /api/login` - User login
- `POST /api/register` - User registration
- `POST /api/register-admin` - Admin registration
- `POST /api/reset-password` - Password reset

### User Management

- `GET /api/users` - List users (admin only)
- `POST /api/users` - Create user (admin only)
- `PATCH /api/users/:id` - Update user (admin only)
- `DELETE /api/users/:id` - Delete user (admin only)

### Secret Management

- `GET /api/secrets` - List secrets
- `POST /api/secrets` - Create secret
- `GET /api/secrets/:id` - Get secret details
- `PUT /api/secrets/:id` - Update secret
- `DELETE /api/secrets/:id` - Delete secret

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Verify PostgreSQL is running
   - Check database credentials
   - Ensure database exists

2. **Frontend Cannot Connect to Backend**
   - Verify backend is running on correct port
   - Check CORS configuration
   - Ensure API URL is correct

3. **Authentication Issues**
   - Check JWT secret configuration
   - Verify token expiration settings
   - Ensure session version is properly managed

### Logs

- Backend logs: `backend/logs/`
- Database logs: PostgreSQL log directory
- Docker logs: `docker-compose logs [service]`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the API documentation

---

**Security Note**: Always change default credentials and secrets before deploying to production. Regular security audits are recommended.
