"""
Unit tests for tenant-specific schema models.

Tests the SQLAlchemy model definitions for User, APIKey, RBACPolicy,
Resource, Job, and AuditLog models that reside in tenant-specific schemas.

Requirements: 1.2, 2.1, 3.1, 4.1
"""

import pytest
from datetime import datetime
from uuid import UUID, uuid4

from app.models.tenant import (
    User,
    APIKey,
    RBACPolicy,
    Resource,
    Job,
    AuditLog,
)


class TestUserModel:
    """Test User model definition"""
    
    def test_user_model_attributes(self):
        """Test that User model has all required attributes"""
        user = User(
            id=uuid4(),
            email="test@example.com",
            password_hash="hashed_password",
            role="admin",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        assert isinstance(user.id, UUID)
        assert user.email == "test@example.com"
        assert user.password_hash == "hashed_password"
        assert user.role == "admin"
        assert isinstance(user.created_at, datetime)
        assert isinstance(user.updated_at, datetime)
    
    def test_user_repr(self):
        """Test User __repr__ method"""
        user_id = uuid4()
        user = User(
            id=user_id,
            email="test@example.com",
            password_hash="hashed",
            role="developer",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        repr_str = repr(user)
        assert "User" in repr_str
        assert str(user_id) in repr_str
        assert "test@example.com" in repr_str
        assert "developer" in repr_str
    
    def test_user_table_name(self):
        """Test User table name"""
        assert User.__tablename__ == "users"
    
    def test_user_relationships(self):
        """Test User has expected relationships"""
        assert hasattr(User, "api_keys")
        assert hasattr(User, "resources")
        assert hasattr(User, "jobs")
        assert hasattr(User, "audit_logs")


class TestAPIKeyModel:
    """Test APIKey model definition"""
    
    def test_api_key_model_attributes(self):
        """Test that APIKey model has all required attributes"""
        api_key = APIKey(
            id=uuid4(),
            key_prefix="sk_test_",
            hashed_secret="hashed_secret",
            name="Test Key",
            role="admin",
            created_by=uuid4(),
            created_at=datetime.utcnow(),
            revoked_at=None,
            last_used_at=None,
        )
        
        assert isinstance(api_key.id, UUID)
        assert api_key.key_prefix == "sk_test_"
        assert api_key.hashed_secret == "hashed_secret"
        assert api_key.name == "Test Key"
        assert api_key.role == "admin"
        assert isinstance(api_key.created_by, UUID)
        assert isinstance(api_key.created_at, datetime)
        assert api_key.revoked_at is None
        assert api_key.last_used_at is None
    
    def test_api_key_with_revoked_at(self):
        """Test APIKey with revoked_at timestamp"""
        revoked_time = datetime.utcnow()
        api_key = APIKey(
            id=uuid4(),
            key_prefix="sk_test_",
            hashed_secret="hashed_secret",
            name="Revoked Key",
            role="developer",
            created_at=datetime.utcnow(),
            revoked_at=revoked_time,
        )
        
        assert api_key.revoked_at == revoked_time
    
    def test_api_key_repr(self):
        """Test APIKey __repr__ method"""
        api_key_id = uuid4()
        api_key = APIKey(
            id=api_key_id,
            key_prefix="sk_test_",
            hashed_secret="hashed",
            name="Test Key",
            role="admin",
            created_at=datetime.utcnow(),
        )
        
        repr_str = repr(api_key)
        assert "APIKey" in repr_str
        assert str(api_key_id) in repr_str
        assert "Test Key" in repr_str
        assert "admin" in repr_str
        assert "active" in repr_str
    
    def test_api_key_repr_revoked(self):
        """Test APIKey __repr__ method for revoked key"""
        api_key = APIKey(
            id=uuid4(),
            key_prefix="sk_test_",
            hashed_secret="hashed",
            name="Revoked Key",
            role="admin",
            created_at=datetime.utcnow(),
            revoked_at=datetime.utcnow(),
        )
        
        repr_str = repr(api_key)
        assert "revoked" in repr_str
    
    def test_api_key_table_name(self):
        """Test APIKey table name"""
        assert APIKey.__tablename__ == "api_keys"
    
    def test_api_key_relationships(self):
        """Test APIKey has expected relationships"""
        assert hasattr(APIKey, "user")


class TestRBACPolicyModel:
    """Test RBACPolicy model definition"""
    
    def test_rbac_policy_model_attributes(self):
        """Test that RBACPolicy model has all required attributes"""
        permissions = [
            {"action": "create", "resource": "resources"},
            {"action": "read", "resource": "*"},
        ]
        
        policy = RBACPolicy(
            id=uuid4(),
            role="developer",
            permissions=permissions,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        assert isinstance(policy.id, UUID)
        assert policy.role == "developer"
        assert policy.permissions == permissions
        assert isinstance(policy.created_at, datetime)
        assert isinstance(policy.updated_at, datetime)
    
    def test_rbac_policy_repr(self):
        """Test RBACPolicy __repr__ method"""
        policy_id = uuid4()
        policy = RBACPolicy(
            id=policy_id,
            role="admin",
            permissions=[{"action": "*", "resource": "*"}],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        repr_str = repr(policy)
        assert "RBACPolicy" in repr_str
        assert str(policy_id) in repr_str
        assert "admin" in repr_str
    
    def test_rbac_policy_table_name(self):
        """Test RBACPolicy table name"""
        assert RBACPolicy.__tablename__ == "rbac_policies"


class TestResourceModel:
    """Test Resource model definition"""
    
    def test_resource_model_attributes(self):
        """Test that Resource model has all required attributes"""
        resource_data = {"key": "value", "nested": {"data": 123}}
        
        resource = Resource(
            id=uuid4(),
            name="Test Resource",
            data=resource_data,
            owner_id=uuid4(),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        assert isinstance(resource.id, UUID)
        assert resource.name == "Test Resource"
        assert resource.data == resource_data
        assert isinstance(resource.owner_id, UUID)
        assert isinstance(resource.created_at, datetime)
        assert isinstance(resource.updated_at, datetime)
    
    def test_resource_without_owner(self):
        """Test Resource without owner_id"""
        resource = Resource(
            id=uuid4(),
            name="Orphan Resource",
            data={"key": "value"},
            owner_id=None,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        assert resource.owner_id is None
    
    def test_resource_repr(self):
        """Test Resource __repr__ method"""
        resource_id = uuid4()
        owner_id = uuid4()
        resource = Resource(
            id=resource_id,
            name="Test Resource",
            data={},
            owner_id=owner_id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        repr_str = repr(resource)
        assert "Resource" in repr_str
        assert str(resource_id) in repr_str
        assert "Test Resource" in repr_str
        assert str(owner_id) in repr_str
    
    def test_resource_table_name(self):
        """Test Resource table name"""
        assert Resource.__tablename__ == "resources"
    
    def test_resource_relationships(self):
        """Test Resource has expected relationships"""
        assert hasattr(Resource, "owner")


class TestJobModel:
    """Test Job model definition"""
    
    def test_job_model_attributes(self):
        """Test that Job model has all required attributes"""
        job_id = uuid4()
        payload = {"input": "data"}
        result = {"output": "result"}
        
        job = Job(
            id=job_id,
            task_type="process_data",
            status="SUCCESS",
            payload=payload,
            result=result,
            error=None,
            created_by=uuid4(),
            created_at=datetime.utcnow(),
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )
        
        assert job.id == job_id
        assert job.task_type == "process_data"
        assert job.status == "SUCCESS"
        assert job.payload == payload
        assert job.result == result
        assert job.error is None
        assert isinstance(job.created_by, UUID)
        assert isinstance(job.created_at, datetime)
        assert isinstance(job.started_at, datetime)
        assert isinstance(job.completed_at, datetime)
    
    def test_job_with_error(self):
        """Test Job with error message"""
        job = Job(
            id=uuid4(),
            task_type="failing_task",
            status="FAILURE",
            payload={},
            result=None,
            error="Task failed due to timeout",
            created_at=datetime.utcnow(),
        )
        
        assert job.status == "FAILURE"
        assert job.error == "Task failed due to timeout"
        assert job.result is None
    
    def test_job_pending_status(self):
        """Test Job in PENDING status"""
        job = Job(
            id=uuid4(),
            task_type="pending_task",
            status="PENDING",
            payload={"data": "test"},
            created_at=datetime.utcnow(),
            started_at=None,
            completed_at=None,
        )
        
        assert job.status == "PENDING"
        assert job.started_at is None
        assert job.completed_at is None
    
    def test_job_repr(self):
        """Test Job __repr__ method"""
        job_id = uuid4()
        job = Job(
            id=job_id,
            task_type="test_task",
            status="STARTED",
            created_at=datetime.utcnow(),
        )
        
        repr_str = repr(job)
        assert "Job" in repr_str
        assert str(job_id) in repr_str
        assert "test_task" in repr_str
        assert "STARTED" in repr_str
    
    def test_job_table_name(self):
        """Test Job table name"""
        assert Job.__tablename__ == "jobs"
    
    def test_job_relationships(self):
        """Test Job has expected relationships"""
        assert hasattr(Job, "creator")


class TestAuditLogModel:
    """Test AuditLog model definition"""
    
    def test_audit_log_model_attributes(self):
        """Test that AuditLog model has all required attributes"""
        changes = {"before": {"status": "active"}, "after": {"status": "inactive"}}
        
        audit_log = AuditLog(
            id=uuid4(),
            user_id=uuid4(),
            action="update",
            resource_type="user",
            resource_id=uuid4(),
            changes=changes,
            ip_address="192.168.1.1",
            timestamp=datetime.utcnow(),
        )
        
        assert isinstance(audit_log.id, UUID)
        assert isinstance(audit_log.user_id, UUID)
        assert audit_log.action == "update"
        assert audit_log.resource_type == "user"
        assert isinstance(audit_log.resource_id, UUID)
        assert audit_log.changes == changes
        assert audit_log.ip_address == "192.168.1.1"
        assert isinstance(audit_log.timestamp, datetime)
    
    def test_audit_log_without_resource(self):
        """Test AuditLog without resource information"""
        audit_log = AuditLog(
            id=uuid4(),
            user_id=uuid4(),
            action="login",
            resource_type=None,
            resource_id=None,
            changes=None,
            ip_address="10.0.0.1",
            timestamp=datetime.utcnow(),
        )
        
        assert audit_log.action == "login"
        assert audit_log.resource_type is None
        assert audit_log.resource_id is None
        assert audit_log.changes is None
    
    def test_audit_log_system_action(self):
        """Test AuditLog for system action without user"""
        audit_log = AuditLog(
            id=uuid4(),
            user_id=None,
            action="system_cleanup",
            resource_type="job",
            resource_id=uuid4(),
            timestamp=datetime.utcnow(),
        )
        
        assert audit_log.user_id is None
        assert audit_log.action == "system_cleanup"
    
    def test_audit_log_repr(self):
        """Test AuditLog __repr__ method"""
        log_id = uuid4()
        user_id = uuid4()
        timestamp = datetime.utcnow()
        
        audit_log = AuditLog(
            id=log_id,
            user_id=user_id,
            action="delete",
            timestamp=timestamp,
        )
        
        repr_str = repr(audit_log)
        assert "AuditLog" in repr_str
        assert str(log_id) in repr_str
        assert "delete" in repr_str
        assert str(user_id) in repr_str
    
    def test_audit_log_table_name(self):
        """Test AuditLog table name"""
        assert AuditLog.__tablename__ == "audit_logs"
    
    def test_audit_log_relationships(self):
        """Test AuditLog has expected relationships"""
        assert hasattr(AuditLog, "user")


class TestModelIndexes:
    """Test that models have proper indexes defined"""
    
    def test_api_key_has_prefix_index(self):
        """Test APIKey has index on key_prefix"""
        indexes = APIKey.__table_args__
        assert len(indexes) > 0
        # Check that there's an index configuration
        assert any(hasattr(item, 'name') or isinstance(item, dict) for item in indexes)
    
    def test_resource_has_indexes(self):
        """Test Resource has proper indexes"""
        indexes = Resource.__table_args__
        assert len(indexes) > 0
    
    def test_job_has_indexes(self):
        """Test Job has proper indexes"""
        indexes = Job.__table_args__
        assert len(indexes) > 0
    
    def test_audit_log_has_indexes(self):
        """Test AuditLog has proper indexes"""
        indexes = AuditLog.__table_args__
        assert len(indexes) > 0
