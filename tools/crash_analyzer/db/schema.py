"""SQLite database schema and operations for crash analysis."""

from __future__ import annotations
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from parsers.crash_log import CrashLog
    from parsers.server_dump import ServerDump, PacketRecord


class CrashDatabase:
    """Manages the crash analysis SQLite database."""

    def __init__(self, db_path: str = "crashes.db"):
        """
        Initialize database connection.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row  # Enable dict-like access
        self._create_schema()

    def _create_schema(self):
        """Create database schema if it doesn't exist."""
        cursor = self.conn.cursor()

        # Crashes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS crashes (
                id INTEGER PRIMARY KEY,
                signature TEXT NOT NULL,
                player_name TEXT,
                crash_timestamp DATETIME,
                map_name TEXT,
                position_x REAL,
                position_y REAL,
                position_z REAL,
                game_uptime_seconds INTEGER,
                time_on_map_seconds INTEGER,
                last_audio TEXT,
                client_log_path TEXT,
                server_dump_path TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Crash packets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS crash_packets (
                id INTEGER PRIMARY KEY,
                crash_id INTEGER REFERENCES crashes(id),
                packet_index INTEGER,
                timestamp_ms INTEGER,
                packet_type TEXT,
                packet_size INTEGER,
                sequence_num INTEGER,
                summary TEXT
            )
        """)

        # Signatures aggregation table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS signatures (
                signature TEXT PRIMARY KEY,
                crash_count INTEGER DEFAULT 0,
                first_seen DATETIME,
                last_seen DATETIME,
                common_packets TEXT,
                common_states TEXT,
                notes TEXT
            )
        """)

        # Indexes
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_crashes_signature
            ON crashes(signature)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_crash_packets_type
            ON crash_packets(packet_type)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_crash_packets_crash_id
            ON crash_packets(crash_id)
        """)

        self.conn.commit()

    def ingest_crash(
        self,
        crash_log: CrashLog,
        server_dump: Optional[ServerDump] = None
    ) -> int:
        """
        Store a crash in the database.

        Args:
            crash_log: Parsed crash log
            server_dump: Matched server dump (if found)

        Returns:
            crash_id of the inserted record
        """
        cursor = self.conn.cursor()

        # Get player name from dump if available
        player_name = server_dump.player_name if server_dump else None

        # Insert crash record
        cursor.execute("""
            INSERT INTO crashes (
                signature,
                player_name,
                crash_timestamp,
                map_name,
                position_x,
                position_y,
                position_z,
                game_uptime_seconds,
                time_on_map_seconds,
                last_audio,
                client_log_path,
                server_dump_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            crash_log.signature,
            player_name,
            crash_log.timestamp,
            crash_log.map_name,
            crash_log.position[0],
            crash_log.position[1],
            crash_log.position[2],
            crash_log.game_uptime_seconds,
            crash_log.time_on_map_seconds,
            crash_log.last_audio,
            crash_log.log_path,
            server_dump.dump_path if server_dump else None
        ))

        crash_id = cursor.lastrowid

        # Insert packets if we have a server dump
        if server_dump:
            for idx, packet in enumerate(server_dump.packets):
                cursor.execute("""
                    INSERT INTO crash_packets (
                        crash_id,
                        packet_index,
                        timestamp_ms,
                        packet_type,
                        packet_size,
                        sequence_num,
                        summary
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    crash_id,
                    idx,
                    packet.timestamp_ms,
                    packet.packet_type,
                    packet.packet_size,
                    packet.sequence_num,
                    packet.summary
                ))

        # Update signature statistics
        self._update_signature_stats(crash_log.signature, crash_log.timestamp)

        self.conn.commit()
        return crash_id

    def _update_signature_stats(self, signature: str, crash_time: datetime):
        """Update aggregated signature statistics."""
        cursor = self.conn.cursor()

        # Check if signature exists
        cursor.execute(
            "SELECT crash_count, first_seen FROM signatures WHERE signature = ?",
            (signature,)
        )
        row = cursor.fetchone()

        if row:
            # Update existing
            cursor.execute("""
                UPDATE signatures
                SET crash_count = crash_count + 1,
                    last_seen = ?
                WHERE signature = ?
            """, (crash_time, signature))
        else:
            # Insert new
            cursor.execute("""
                INSERT INTO signatures (signature, crash_count, first_seen, last_seen)
                VALUES (?, 1, ?, ?)
            """, (signature, crash_time, crash_time))

        self.conn.commit()

    def get_signature_count(self, signature: str) -> int:
        """Get the number of crashes for a signature."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT crash_count FROM signatures WHERE signature = ?",
            (signature,)
        )
        row = cursor.fetchone()
        return row['crash_count'] if row else 0

    def get_crashes_by_signature(self, signature: str) -> List[Dict[str, Any]]:
        """Get all crashes with a specific signature."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM crashes WHERE signature = ? ORDER BY crash_timestamp DESC
        """, (signature,))
        return [dict(row) for row in cursor.fetchall()]

    def get_packets_for_crash(self, crash_id: int) -> List[Dict[str, Any]]:
        """Get all packets for a specific crash."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM crash_packets
            WHERE crash_id = ?
            ORDER BY packet_index ASC
        """, (crash_id,))
        return [dict(row) for row in cursor.fetchall()]

    def get_all_signatures(self) -> List[Dict[str, Any]]:
        """Get all signatures ordered by crash count."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM signatures ORDER BY crash_count DESC
        """)
        return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict[str, Any]:
        """Get overall database statistics."""
        cursor = self.conn.cursor()

        # Total crashes
        cursor.execute("SELECT COUNT(*) as total FROM crashes")
        total_crashes = cursor.fetchone()['total']

        # Unique signatures
        cursor.execute("SELECT COUNT(*) as unique_count FROM signatures")
        unique_signatures = cursor.fetchone()['unique_count']

        # Crashes with server dumps
        cursor.execute("SELECT COUNT(*) as matched FROM crashes WHERE server_dump_path IS NOT NULL")
        matched_crashes = cursor.fetchone()['matched']

        # Date range
        cursor.execute("SELECT MIN(crash_timestamp) as first, MAX(crash_timestamp) as last FROM crashes")
        dates = cursor.fetchone()

        # Top signatures
        cursor.execute("""
            SELECT signature, crash_count
            FROM signatures
            ORDER BY crash_count DESC
            LIMIT 10
        """)
        top_signatures = [dict(row) for row in cursor.fetchall()]

        return {
            'total_crashes': total_crashes,
            'unique_signatures': unique_signatures,
            'matched_crashes': matched_crashes,
            'unmatched_crashes': total_crashes - matched_crashes,
            'first_crash': dates['first'],
            'last_crash': dates['last'],
            'top_signatures': top_signatures
        }

    def close(self):
        """Close database connection."""
        self.conn.close()
