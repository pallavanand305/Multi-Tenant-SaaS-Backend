# Multi-Tenant SaaS Platform

Enterprise-grade multi-tenant backend platform built with FastAPI, demonstrating production-level architecture patterns for tenant isolation, authentication, usage metering, and infrastructure automation.

## Features

- **Multi-Tenant Architecture**: Schema-based tenant isolation with PostgreSQL
- **Authentication & Authorization**: JWT tokens and API keys with RBAC
- **Usage Metering**: Track API requests, compute time, and data transfer per tenant
- **Rate Limiting**: Configurable per-tenant rate limits with Redis
- **Background Jobs**: Celery-based asynchronous task processing
- **Autoscaling Simulation**: Per-tenant resource scaling decisions
- **Infrastructure as Code**: Complete Terraform configurations for AWS
- **CI/CD Pipeline**: GitHub Actions with automated testing and deployment
- **Observability**: Structured logging, Prometheus metrics, and health checks

## Architecture

The platform implements schema-based multi-tenancy where each tenant gets a dedicated PostgreSQL schema within a shared database cluster. This provides strong isolation while maintaining operational efficiency.

### Technology Stack

- **API Framework**: FastAPI 0.104+ (Python 3.11+)
- **Database**: PostgreSQL 15+ with tenant-specific schemas
- **Authentication**: JWT tokens (PyJWT) with RS256 signing
- **Background Jobs**: Celery 5+ with Redis broker
- **Rate Limiting**: Redis-backed token bucket algorithm
- **Cloud Provider**: AWS (ECS, RDS, ElastiCache, SQS)
- **Infrastructure**: Terraform 1.6+
- **CI/CD**: GitHub Actions

## Project Structure

```
.
├── app/                    # Application code
│   ├── api/               # API endpoints
│   ├── auth/              # Authentication & authorization
│   ├── middleware/        # Request middleware
│   ├── models/            # Database models
│   ├── services/          # Business logic services
│   ├── tasks/             # Celery background tasks
│   ├── errors/            # Error handling
│   ├── logging/           # Logging configuration
│   └── monitoring/        # Metrics and monitoring
├── tests/                 # Test suite
│   ├── unit/             # Unit tests
│   ├── properties/       # Property-based tests
│   └── integration/      # Integration tests
├── terraform/            # Infrastructure as code
├── alembic/              # Database migrations
├── main.py               # Application entry point
├── requirements.txt      # Production dependencies
└── requirements-dev.txt  # Development dependencies
```

## Getting Started

### Prerequisites

- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- Docker (optional, for local development)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd multi-tenant-saas-platform
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Generate JWT keys:
```bash
mkdir -p keys
openssl genrsa -out keys/jwt_private.pem 2048
openssl rsa -in keys/jwt_private.pem -pubout -out keys/jwt_public.pem
```

6. Initialize the database:
```bash
# Create database
createdb saas_platform

# Run migrations (after Alembic setup)
alembic upgrade head
```

### Running the Application

**Development mode:**
```bash
python main.py
```

**Production mode with Uvicorn:**
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

**Using Docker Compose:**
```bash
docker-compose up
```

### Running Tests

**All tests:**
```bash
pytest
```

**Unit tests only:**
```bash
pytest tests/unit -v
```

**Property-based tests:**
```bash
pytest tests/properties -v --hypothesis-show-statistics
```

**Integration tests:**
```bash
pytest tests/integration -v
```

**With coverage:**
```bash
pytest --cov=app --cov-report=html
```

## API Documentation

Once the application is running, access the interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

## Development

### Code Quality

The project uses the following tools for code quality:

- **Ruff**: Fast Python linter
- **MyPy**: Static type checking
- **Black**: Code formatting

Run checks:
```bash
ruff check .
mypy .
black --check .
```

Auto-fix issues:
```bash
ruff check --fix .
black .
```

### Database Migrations

Create a new migration:
```bash
alembic revision --autogenerate -m "Description of changes"
```

Apply migrations:
```bash
alembic upgrade head
```

Rollback migration:
```bash
alembic downgrade -1
```

## Deployment

### Infrastructure Provisioning

The platform includes complete Terraform configurations for AWS deployment.

```bash
cd terraform/environments/production
terraform init
terraform plan
terraform apply
```

### CI/CD Pipeline

The GitHub Actions workflow automatically:
1. Runs tests on pull requests
2. Builds Docker images on push to main/develop
3. Deploys to staging on push to develop
4. Deploys to production on push to main (with approval)

## License

This project is for portfolio demonstration purposes.

## Contact

For questions or feedback, please open an issue in the repository.
