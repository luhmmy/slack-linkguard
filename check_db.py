import database

workspaces = database.get_all_workspaces()
print(f'Found {len(workspaces)} workspaces:')
for w in workspaces:
    print(f"  - {w['team_name']} ({w['team_id']})")
    print(f"    bot_user_id: {w.get('bot_user_id', 'MISSING')}")
