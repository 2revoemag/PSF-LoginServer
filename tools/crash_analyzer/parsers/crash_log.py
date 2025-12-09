"""Parser for PlanetSide client crash logs."""

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple


@dataclass
class CrashLog:
    """Structured representation of a PlanetSide crash log."""

    version: str
    timestamp: datetime
    game_uptime_seconds: int
    position: Tuple[float, float, float]
    map_name: str
    time_on_map_seconds: int
    exception_address: str
    reading_address: str
    last_audio: Optional[str]
    signature: str  # Generated from exception + reading address

    # Original file path for reference
    log_path: str


class CrashLogParser:
    """Parse PlanetSide crash log files."""

    # Regex patterns for extracting data
    VERSION_RE = re.compile(r'^([\d\.]+)\s*$')
    TIMESTAMP_RE = re.compile(r'Timestamp:\s*(.+)')
    UPTIME_RE = re.compile(r'Game Uptime:\s*(\d+)\s*seconds')
    POSITION_RE = re.compile(r'Position last frame:\s*([\d\.\-]+),\s*([\d\.\-]+),\s*([\d\.\-]+)')
    MAP_RE = re.compile(r'Map name:\s*(\w+)')
    TIME_ON_MAP_RE = re.compile(r'Time On Map:\s*(\d+)\s*seconds')
    EXCEPTION_RE = re.compile(r'Unhandled exception \w+ at (0x[0-9A-F]+)', re.IGNORECASE)
    READING_RE = re.compile(r'Application was trying to read from (0x[0-9A-F]+)', re.IGNORECASE)
    AUDIO_RE = re.compile(r'Last Sample3d:\s*([^\[\s]+)')

    @classmethod
    def parse(cls, file_path: str) -> CrashLog:
        """
        Parse a crash log file.

        Args:
            file_path: Path to planetside_crash.log

        Returns:
            Parsed CrashLog object

        Raises:
            ValueError: If required fields are missing or malformed
        """
        path = Path(file_path)
        if not path.exists():
            raise ValueError(f"Crash log not found: {file_path}")

        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Extract all fields
        version = cls._extract_version(content)
        timestamp = cls._extract_timestamp(content)
        uptime = cls._extract_uptime(content)
        position = cls._extract_position(content)
        map_name = cls._extract_map_name(content)
        time_on_map = cls._extract_time_on_map(content)
        exception_addr = cls._extract_exception_address(content)
        reading_addr = cls._extract_reading_address(content)
        last_audio = cls._extract_last_audio(content)

        # Generate signature
        signature = cls._generate_signature(exception_addr, reading_addr)

        return CrashLog(
            version=version,
            timestamp=timestamp,
            game_uptime_seconds=uptime,
            position=position,
            map_name=map_name,
            time_on_map_seconds=time_on_map,
            exception_address=exception_addr,
            reading_address=reading_addr,
            last_audio=last_audio,
            signature=signature,
            log_path=str(path.absolute())
        )

    @classmethod
    def _extract_version(cls, content: str) -> str:
        """Extract version from first line."""
        first_line = content.split('\n')[0].strip()
        match = cls.VERSION_RE.match(first_line)
        if not match:
            raise ValueError("Could not extract version from crash log")
        return match.group(1)

    @classmethod
    def _extract_timestamp(cls, content: str) -> datetime:
        """Extract crash timestamp."""
        match = cls.TIMESTAMP_RE.search(content)
        if not match:
            raise ValueError("Could not extract timestamp from crash log")

        timestamp_str = match.group(1).strip()
        # Try to parse: "Mon Dec 08 15:33:03 2025"
        try:
            return datetime.strptime(timestamp_str, '%a %b %d %H:%M:%S %Y')
        except ValueError:
            # Fallback formats
            for fmt in ['%Y-%m-%d %H:%M:%S', '%m/%d/%Y %H:%M:%S']:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
            raise ValueError(f"Could not parse timestamp: {timestamp_str}")

    @classmethod
    def _extract_uptime(cls, content: str) -> int:
        """Extract game uptime in seconds."""
        match = cls.UPTIME_RE.search(content)
        if not match:
            raise ValueError("Could not extract game uptime from crash log")
        return int(match.group(1))

    @classmethod
    def _extract_position(cls, content: str) -> Tuple[float, float, float]:
        """Extract player position (x, y, z)."""
        match = cls.POSITION_RE.search(content)
        if not match:
            raise ValueError("Could not extract position from crash log")
        return (float(match.group(1)), float(match.group(2)), float(match.group(3)))

    @classmethod
    def _extract_map_name(cls, content: str) -> str:
        """Extract map name."""
        match = cls.MAP_RE.search(content)
        if not match:
            raise ValueError("Could not extract map name from crash log")
        return match.group(1)

    @classmethod
    def _extract_time_on_map(cls, content: str) -> int:
        """Extract time spent on current map in seconds."""
        match = cls.TIME_ON_MAP_RE.search(content)
        if not match:
            raise ValueError("Could not extract time on map from crash log")
        return int(match.group(1))

    @classmethod
    def _extract_exception_address(cls, content: str) -> str:
        """Extract exception memory address."""
        match = cls.EXCEPTION_RE.search(content)
        if not match:
            raise ValueError("Could not extract exception address from crash log")
        return match.group(1).upper()

    @classmethod
    def _extract_reading_address(cls, content: str) -> str:
        """Extract the memory address being read from."""
        match = cls.READING_RE.search(content)
        if not match:
            raise ValueError("Could not extract reading address from crash log")
        return match.group(1).upper()

    @classmethod
    def _extract_last_audio(cls, content: str) -> Optional[str]:
        """Extract last audio sample (optional field)."""
        match = cls.AUDIO_RE.search(content)
        return match.group(1) if match else None

    @classmethod
    def _generate_signature(cls, exception_addr: str, reading_addr: str) -> str:
        """
        Generate crash signature from addresses.

        Format: {exception_address}_{reading_offset}
        Example: 0x008EED30_0x40

        The reading address offset is just the low address value being read,
        which often indicates the field offset in a struct that was null.
        """
        # Extract just the offset part of reading address
        offset = reading_addr  # Use full address for now
        return f"{exception_addr}_{offset}"
