"""
Unit tests for main application
"""

import pytest
from fastapi.testclient import TestClient
from main import app


@pytest.fixture
def client():
    """Create test client"""
    return TestClient(app)


def test_root_endpoint(client):
    """Test root endpoint returns API information"""
    response = client.get("/")
    assert response.status_code == 200
    
    data = response.json()
    assert "name" in data
    assert "version" in data
    assert "environment" in data
    assert data["version"] == "1.0.0"


def test_openapi_schema(client):
    """Test OpenAPI schema is generated"""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    
    schema = response.json()
    assert "openapi" in schema
    assert "info" in schema
    assert schema["info"]["title"] == "Multi-Tenant SaaS Platform API"


def test_docs_endpoint(client):
    """Test Swagger UI docs endpoint is accessible"""
    response = client.get("/docs")
    assert response.status_code == 200


def test_redoc_endpoint(client):
    """Test ReDoc endpoint is accessible"""
    response = client.get("/redoc")
    assert response.status_code == 200
