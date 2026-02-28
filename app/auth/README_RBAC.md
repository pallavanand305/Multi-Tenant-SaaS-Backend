# RBAC Policy Engine

Role-Based Access Control (RBAC) engine for the multi-tenant SaaS platform.

## Overview

The RBAC engine provides fine-grained permission control based on user roles. It supports:

- **Default roles**: admin, developer, read_only
- **Custom tenant-specific roles**: Tenants can define their own roles and permissions
- **Wildcard permissions**: Support for `*` in actions and resources
- **Policy caching**: Efficient caching of tenant-specific policies

## Default Roles

### Admin
- **Permissions**: `*:*` (all actions on all resources)
- **Use case**: Full system access for tenant administrators

### Developer
- **Permissions**:
  - `read:*` - Read access to all resources
  - `create:resources` - Create resources
  - `update:resources` - Update resources
  - `delete:resources` - Delete resources
  - `read:jobs` - Read background jobs
  - `create:jobs` - Create background jobs
  - `read:usage` - Read usage metrics
- **Use case**: Application developers who need to manage resources and jobs

### Read-Only
- **Permissions**: `read:*` (read-only access to all resources)
- **Use case**: Auditors, viewers, or monitoring systems

## Usage Examples

### Basic Permission Check

```python
from app.auth.rbac import RBACEngine

engine = RBACEngine()

# Check if developer can read resources
allowed = engine.check_permission("developer", "read", "resources")
# Returns: True

# Check if read_only can delete resources
allowed = engine.check_permission("read_only", "delete", "resources")
# Returns: False

# Check if admin can do anything
allowed = engine.check_permission("admin", "delete", "users")
# Returns: True
```

### Using with AuthService

```python
from app.auth.auth_service import AuthService

auth_service = AuthService()

# Check permission using role from authenticated user
if not auth_service.check_permission(user.role, "create", "resources"):
    raise AuthorizationError("Insufficient permissions")
```

### Tenant-Specific Policies

```python
from app.auth.rbac import RBACEngine
from sqlalchemy.ext.asyncio import AsyncSession

engine = RBACEngine()

# Load tenant-specific policies from database
async def check_with_tenant_policy(db: AsyncSession, tenant_id: str):
    allowed = await engine.check_permission_with_db(
        db=db,
        tenant_id=tenant_id,
        role="custom_role",
        action="read",
        resource="resources"
    )
    return allowed
```

### Creating Custom Tenant Policies

```python
from app.models.tenant import RBACPolicy
from sqlalchemy.ext.asyncio import AsyncSession

async def create_custom_role(db: AsyncSession):
    # Create a custom role with specific permissions
    policy = RBACPolicy(
        role="data_analyst",
        permissions=[
            {"action": "read", "resource": "resources"},
            {"action": "read", "resource": "usage"},
            {"action": "read", "resource": "jobs"}
        ]
    )
    db.add(policy)
    await db.commit()
```

### Middleware Integration

```python
from fastapi import Request, HTTPException
from app.auth.rbac import RBACEngine

async def check_permission_middleware(request: Request, action: str, resource: str):
    """Middleware to check permissions before processing request"""
    
    # Get role from request state (set by auth middleware)
    role = request.state.role
    tenant_id = request.state.tenant_id
    db = request.state.db_session
    
    # Check permission
    engine = RBACEngine()
    allowed = await engine.check_permission_with_db(
        db=db,
        tenant_id=tenant_id,
        role=role,
        action=action,
        resource=resource
    )
    
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "error": {
                    "code": "INSUFFICIENT_PERMISSIONS",
                    "message": f"Role '{role}' does not have permission to {action} {resource}"
                }
            }
        )
```

### Endpoint Protection

```python
from fastapi import APIRouter, Depends, HTTPException
from app.auth.auth_service import AuthService

router = APIRouter()
auth_service = AuthService()

@router.post("/api/v1/resources")
async def create_resource(
    request: Request,
    data: ResourceCreateRequest
):
    # Check permission
    if not auth_service.check_permission(request.state.role, "create", "resources"):
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions to create resources"
        )
    
    # Process request
    # ...
```

## Permission Format

Permissions follow the format: `action:resource`

### Actions
- `create` - Create new resources
- `read` - Read/view resources
- `update` - Modify existing resources
- `delete` - Remove resources
- `*` - All actions (wildcard)

### Resources
- `users` - User management
- `api_keys` - API key management
- `resources` - Tenant resources
- `jobs` - Background jobs
- `usage` - Usage metrics
- `*` - All resources (wildcard)

### Wildcard Examples
- `*:*` - All actions on all resources (admin)
- `read:*` - Read access to all resources
- `*:users` - All actions on users resource
- `create:resources` - Create resources only

## Caching

The RBAC engine caches tenant-specific policies to avoid repeated database queries:

```python
engine = RBACEngine()

# First call loads from database
await engine.check_permission_with_db(db, tenant_id, role, action, resource)

# Subsequent calls use cache
await engine.check_permission_with_db(db, tenant_id, role, action, resource)

# Clear cache when policies are updated
engine.clear_cache(tenant_id)

# Or clear all caches
engine.clear_cache()
```

## Testing

The RBAC engine includes comprehensive unit tests:

```bash
# Run all RBAC tests
pytest tests/unit/test_rbac.py -v

# Run specific test class
pytest tests/unit/test_rbac.py::TestRBACEngine -v

# Run with coverage
pytest tests/unit/test_rbac.py --cov=app.auth.rbac
```

## Requirements Mapping

- **Requirement 3.1**: Evaluate RBAC policy for user's role
- **Requirement 3.2**: Support admin, developer, and read-only roles
- **Requirement 3.3**: Verify user's role permits requested action
- **Requirement 3.4**: Reject requests when role doesn't permit action
- **Requirement 3.5**: RBAC policy configurable per tenant
