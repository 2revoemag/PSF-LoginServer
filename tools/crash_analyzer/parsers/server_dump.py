"""Parser for server packet dump JSON files."""

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple


@dataclass
class PacketRecord:
    """A single packet sent to the client."""
    timestamp_ms: int      # ms since session start
    packet_type: str       # e.g., "ObjectCreateMessage"
    packet_size: int       # bytes
    sequence_num: int      # protocol sequence number
    summary: str           # key fields summary


@dataclass
class ServerDump:
    """Structured representation of a server packet dump."""

    session_id: str
    player_name: Optional[str]
    account_name: Optional[str]
    zone: Optional[str]
    position: Optional[Tuple[float, float, float]]
    last_known_state: str
    session_duration_ms: int
    total_packets_sent: int
    disconnect_type: str
    disconnect_time: datetime
    packets: List[PacketRecord]

    # Original file path for reference
    dump_path: str


class ServerDumpParser:
    """Parse server packet dump JSON files."""

    @classmethod
    def parse(cls, file_path: str) -> ServerDump:
        """
        Parse a server dump JSON file.

        Args:
            file_path: Path to packet_dump_*.json

        Returns:
            Parsed ServerDump object

        Raises:
            ValueError: If required fields are missing or malformed
        """
        path = Path(file_path)
        if not path.exists():
            raise ValueError(f"Server dump not found: {file_path}")

        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Parse position (may be null)
        position = None
        if data.get('position'):
            pos_list = data['position']
            if isinstance(pos_list, list) and len(pos_list) == 3:
                position = (float(pos_list[0]), float(pos_list[1]), float(pos_list[2]))

        # Parse disconnect time
        disconnect_time_str = data.get('disconnectTime')
        if not disconnect_time_str:
            raise ValueError("Missing disconnectTime in server dump")

        # Try ISO format first: "2025-12-08T15:33:03Z"
        try:
            disconnect_time = datetime.fromisoformat(disconnect_time_str.replace('Z', '+00:00'))
        except ValueError:
            # Fallback to other formats
            for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S']:
                try:
                    disconnect_time = datetime.strptime(disconnect_time_str, fmt)
                    break
                except ValueError:
                    continue
            else:
                raise ValueError(f"Could not parse disconnectTime: {disconnect_time_str}")

        # Parse packets
        packets = []
        for p in data.get('packets', []):
            packets.append(PacketRecord(
                timestamp_ms=p.get('timestamp', 0),
                packet_type=p.get('packetType', p.get('type', 'Unknown')),
                packet_size=p.get('packetSize', p.get('size', 0)),
                sequence_num=p.get('sequenceNum', p.get('seq', 0)),
                summary=p.get('summary', '')
            ))

        return ServerDump(
            session_id=data.get('sessionId', ''),
            player_name=data.get('playerName'),
            account_name=data.get('accountName'),
            zone=data.get('zone'),
            position=position,
            last_known_state=data.get('lastKnownState', 'unknown'),
            session_duration_ms=data.get('sessionDuration', 0),
            total_packets_sent=data.get('totalPacketsSent', 0),
            disconnect_type=data.get('disconnectType', 'unknown'),
            disconnect_time=disconnect_time,
            packets=packets,
            dump_path=str(path.absolute())
        )
