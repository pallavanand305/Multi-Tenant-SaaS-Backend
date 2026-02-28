#!/usr/bin/env python3
"""
Initialize test database schema

Creates the platform_shared schema and all required tables for testing.
"""

import asyncio
import sys
from sqlalchemy import text

# Add parent directory to path
sys.path.insert(0, '.')

from app.database import engine, Base
from app.models import shared, tenant


async def create_test_schema():
    """Create database schema for testing"""
    try:
        async with engine.begin() as conn:
            # Create platform_shared schema
            await conn.execute(text('CREATE SCHEMA IF NOT EXISTS platform_shared'))
            print("✓ Created platform_shared schema")
            
            # Create all tables
            await conn.run_sync(Base.metadata.create_all)
            print("✓ Created all tables")
            
            # Verify tables were created
            result = await conn.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'platform_shared'
                ORDER BY table_name
            """))
            tables = [row[0] for row in result]
            print(f"✓ Tables created: {', '.join(tables)}")
        
        await engine.dispose()
        print("\n✅ Database schema initialized successfully")
        return 0
        
    except Exception as e:
        print(f"\n❌ Error initializing database schema: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(create_test_schema())
    sys.exit(exit_code)
