import database

print('✓ Database module loaded successfully')
print(f'✓ Using: {"PostgreSQL" if database.USE_POSTGRES else "SQLite"}')
print(f'✓ Workspaces: {database.get_workspace_count()}')
