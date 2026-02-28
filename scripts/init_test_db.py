#!/usr/bin/env python3
"""
Initialize test database schema

Creates the platform_shared schema and all required tables for testing.
Also creates a test tenant schema with tenant-specific tables.
"""

import asyncio
import sys
from sqlalchemy import text

# Add parent directory to path
sys.path.insert(0, '.')

from app.database import engine, SharedBase, TenantBase
from app.models import shared, tenant


async def create_test_schema():
    """Create database schema for testing"""
    try:
        async with engine.begin() as conn:
            # Create platform_shared schema
            await conn.execute(text('CREATE SCHEMA IF NOT EXISTS platform_shared'))
            print("✓ Created platform_shared schema")
            
            # Create shared tables (in platform_shared schema)
            await conn.run_sync(SharedBase.metadata.create_all)
            print("✓ Created shared platform tables")
            
            # Verify shared tables were created
            result = await conn.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'platform_shared'
                ORDER BY table_name
            """))
            shared_tables = [row[0] for row in result]
            print(f"  Shared tables: {', '.join(shared_tables)}")
            
            # Create a test tenant schema for unit tests
            test_tenant_schema = "tenant_test"
            await conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS {test_tenant_schema}'))
            print(f"✓ Created {test_tenant_schema} schema")
            
            # Set search_path to tenant schema and create tenant tables
            await conn.execute(text(f'SET search_path TO {test_tenant_schema}'))
            await conn.run_sync(TenantBase.metadata.create_all)
            print(f"✓ Created tenant-specific tables in {test_tenant_schema}")
            
            # Verify tenant tables were created
            result = await conn.execute(text(f"""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = '{test_tenant_schema}'
                ORDER BY table_name
            """))
            tenant_tables = [row[0] for row in result]
            print(f"  Tenant tables: {', '.join(tenant_tables)}")
            
            # Reset search_path
            await conn.execute(text('SET search_path TO public'))
        
        await engine.dispose()
        print("\n✅ Database schema initialized successfully")
        print(f"   - Shared schema: platform_shared ({len(shared_tables)} tables)")
        print(f"   - Tenant schema: {test_tenant_schema} ({len(tenant_tables)} tables)")
        return 0
        
    except Exception as e:
        print(f"\n❌ Error initializing database schema: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(create_test_schema())
    sys.exit(exit_code)
