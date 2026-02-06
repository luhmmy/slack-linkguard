"""
Database layer for Slack LinkGuard multi-workspace support.
Stores OAuth tokens and workspace information using SQLite.
"""

import sqlite3
import logging
from datetime import datetime
from typing import Optional, Dict, List
from contextlib import contextmanager

logger = logging.getLogger(__name__)

DATABASE_PATH = "workspaces.db"


@contextmanager
def get_db_connection():
    """Context manager for database connections."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        conn.close()


def init_database():
    """Initialize the database schema."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS workspaces (
                team_id TEXT PRIMARY KEY,
                team_name TEXT NOT NULL,
                bot_token TEXT NOT NULL,
                bot_user_id TEXT,
                installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        logger.info("Database initialized successfully")


def save_workspace(team_id: str, team_name: str, bot_token: str, bot_user_id: str = None):
    """
    Save or update workspace installation data.
    
    Args:
        team_id: Slack team/workspace ID
        team_name: Slack team/workspace name
        bot_token: OAuth bot access token
        bot_user_id: Bot user ID (optional)
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO workspaces (team_id, team_name, bot_token, bot_user_id, installed_at, last_active)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(team_id) DO UPDATE SET
                team_name = excluded.team_name,
                bot_token = excluded.bot_token,
                bot_user_id = excluded.bot_user_id,
                last_active = excluded.last_active
        """, (team_id, team_name, bot_token, bot_user_id, datetime.utcnow(), datetime.utcnow()))
        logger.info(f"Saved workspace: {team_name} ({team_id})")


def get_workspace_token(team_id: str) -> Optional[str]:
    """
    Retrieve bot token for a specific workspace.
    
    Args:
        team_id: Slack team/workspace ID
        
    Returns:
        Bot token if found, None otherwise
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT bot_token FROM workspaces WHERE team_id = ?", (team_id,))
        row = cursor.fetchone()
        if row:
            # Update last_active timestamp
            cursor.execute(
                "UPDATE workspaces SET last_active = ? WHERE team_id = ?",
                (datetime.utcnow(), team_id)
            )
            return row["bot_token"]
        return None


def get_all_workspaces() -> List[Dict]:
    """
    Get all installed workspaces.
    
    Returns:
        List of workspace dictionaries
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT team_id, team_name, bot_user_id, installed_at, last_active
            FROM workspaces
            ORDER BY installed_at DESC
        """)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def delete_workspace(team_id: str):
    """
    Remove a workspace (uninstallation).
    
    Args:
        team_id: Slack team/workspace ID
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM workspaces WHERE team_id = ?", (team_id,))
        logger.info(f"Deleted workspace: {team_id}")


def get_workspace_count() -> int:
    """Get total number of installed workspaces."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM workspaces")
        row = cursor.fetchone()
        return row["count"] if row else 0


# Initialize database on module import
init_database()
