.PHONY: help install test lint format run docker-up docker-down clean

help:
	@echo "Multi-Tenant SaaS Platform - Available Commands"
	@echo "================================================"
	@echo "install       - Install dependencies"
	@echo "test          - Run all tests"
	@echo "test-unit     - Run unit tests only"
	@echo "test-property - Run property-based tests only"
	@echo "test-cov      - Run tests with coverage report"
	@echo "lint          - Run linting checks"
	@echo "format        - Format code with black"
	@echo "run           - Run the application locally"
	@echo "docker-up     - Start all services with Docker Compose"
	@echo "docker-down   - Stop all Docker services"
	@echo "clean         - Remove generated files"

install:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

test:
	pytest tests/ -v

test-unit:
	pytest tests/unit -v

test-property:
	pytest tests/properties -v --hypothesis-show-statistics

test-integration:
	pytest tests/integration -v

test-cov:
	pytest tests/ -v --cov=app --cov-report=html --cov-report=term

lint:
	ruff check .
	mypy .

format:
	black .
	ruff check --fix .

run:
	python main.py

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	find . -type d -name "htmlcov" -exec rm -rf {} +
	find . -type f -name ".coverage" -delete
	find . -type f -name "coverage.xml" -delete
