#!/usr/bin/env python3
"""
PlanetSide Crash Analyzer CLI

Parses client crash logs and server packet dumps, correlates them,
and analyzes patterns to help identify root causes.
"""

import sys
from pathlib import Path
from typing import Optional

import click

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from parsers.crash_log import CrashLogParser
from parsers.server_dump import ServerDumpParser
from db.schema import CrashDatabase
from analysis.correlate import correlate_crash_to_dump
from analysis.patterns import analyze_signature_patterns


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """PlanetSide Crash Analyzer - correlate crash logs with server dumps."""
    pass


@cli.command()
@click.option('--client-log', required=True, type=click.Path(exists=True),
              help='Path to planetside_crash.log')
@click.option('--server-dump', type=click.Path(exists=True),
              help='Path to server packet dump JSON (optional)')
@click.option('--db', default='crashes.db', type=click.Path(),
              help='Path to SQLite database (default: crashes.db)')
def ingest(client_log: str, server_dump: Optional[str], db: str):
    """
    Ingest a single crash log (and optionally its server dump) into the database.

    Example:
        crash_analyzer ingest --client-log crash.log --server-dump dump.json
    """
    click.echo("=" * 70)
    click.echo("CRASH ANALYZER - INGEST")
    click.echo("=" * 70)

    # Parse crash log
    click.echo(f"\nParsing crash log: {client_log}")
    try:
        crash = CrashLogParser.parse(client_log)
    except Exception as e:
        click.echo(f"ERROR: Failed to parse crash log: {e}", err=True)
        sys.exit(1)

    click.echo(f"  Signature:  {crash.signature}")
    click.echo(f"  Timestamp:  {crash.timestamp}")
    click.echo(f"  Map:        {crash.map_name}")
    click.echo(f"  Position:   ({crash.position[0]:.2f}, {crash.position[1]:.2f}, {crash.position[2]:.2f})")
    click.echo(f"  Uptime:     {crash.game_uptime_seconds}s")

    # Parse server dump if provided
    dump = None
    if server_dump:
        click.echo(f"\nParsing server dump: {server_dump}")
        try:
            dump = ServerDumpParser.parse(server_dump)
        except Exception as e:
            click.echo(f"WARNING: Failed to parse server dump: {e}", err=True)
        else:
            click.echo(f"  Player:     {dump.player_name or 'Unknown'}")
            click.echo(f"  Zone:       {dump.zone or 'Unknown'}")
            click.echo(f"  Packets:    {len(dump.packets)}")
            click.echo(f"  Duration:   {dump.session_duration_ms // 1000}s")

            # Attempt correlation
            click.echo("\nAttempting correlation...")
            is_match, reason = correlate_crash_to_dump(crash, dump)
            if is_match:
                click.echo(click.style(f"  MATCH: {reason}", fg='green'))
            else:
                click.echo(click.style(f"  NO MATCH: {reason}", fg='yellow'))
                if click.confirm("Store anyway?", default=True):
                    pass
                else:
                    click.echo("Aborted.")
                    sys.exit(0)
    else:
        click.echo("\nNo server dump provided - storing crash log only")

    # Store in database
    click.echo(f"\nStoring in database: {db}")
    database = CrashDatabase(db)
    try:
        crash_id = database.ingest_crash(crash, dump)
        click.echo(f"  Stored as crash_id: {crash_id}")

        # Check signature count
        sig_count = database.get_signature_count(crash.signature)
        click.echo(f"\n  This signature has been seen {sig_count} time(s)")

        if sig_count > 1:
            click.echo(f"\n  Tip: Run 'crash_analyzer investigate {crash.signature}' for pattern analysis")

    finally:
        database.close()

    click.echo("\n" + "=" * 70)
    click.echo("INGEST COMPLETE")
    click.echo("=" * 70)


@cli.command()
@click.option('--client-logs', required=True, type=click.Path(exists=True, file_okay=False),
              help='Directory containing crash logs')
@click.option('--server-dumps', type=click.Path(exists=True, file_okay=False),
              help='Directory containing server dumps (optional)')
@click.option('--db', default='crashes.db', type=click.Path(),
              help='Path to SQLite database (default: crashes.db)')
def ingest_dir(client_logs: str, server_dumps: Optional[str], db: str):
    """
    Bulk ingest crash logs and server dumps from directories.

    Example:
        crash_analyzer ingest-dir --client-logs ./logs --server-dumps ./dumps
    """
    click.echo("=" * 70)
    click.echo("CRASH ANALYZER - BULK INGEST")
    click.echo("=" * 70)

    logs_dir = Path(client_logs)
    dumps_dir = Path(server_dumps) if server_dumps else None

    # Find all crash logs
    crash_files = list(logs_dir.glob('**/*.log'))
    click.echo(f"\nFound {len(crash_files)} crash log(s)")

    # Find all server dumps
    dump_files = []
    if dumps_dir:
        dump_files = list(dumps_dir.glob('**/*.json'))
        click.echo(f"Found {len(dump_files)} server dump(s)")

    database = CrashDatabase(db)
    matched = 0
    unmatched = 0
    errors = 0

    try:
        with click.progressbar(crash_files, label='Processing crashes') as bar:
            for log_file in bar:
                try:
                    # Parse crash log
                    crash = CrashLogParser.parse(str(log_file))

                    # Try to find matching dump
                    dump = None
                    if dumps_dir:
                        dump = _find_matching_dump(crash, dump_files)

                    # Store
                    database.ingest_crash(crash, dump)

                    if dump:
                        matched += 1
                    else:
                        unmatched += 1

                except Exception as e:
                    click.echo(f"\nERROR processing {log_file}: {e}", err=True)
                    errors += 1

    finally:
        database.close()

    # Summary
    click.echo("\n" + "=" * 70)
    click.echo("BULK INGEST COMPLETE")
    click.echo("=" * 70)
    click.echo(f"  Processed:  {len(crash_files)} crash logs")
    click.echo(f"  Matched:    {matched} (with server dumps)")
    click.echo(f"  Unmatched:  {unmatched} (no dump found)")
    click.echo(f"  Errors:     {errors}")


def _find_matching_dump(crash, dump_files, player_name: Optional[str] = None):
    """
    Try to find a server dump that matches this crash.

    Matching strategy - score all candidates on multiple factors:
    1. Player name match (if provided) - strong signal
    2. Timestamp proximity (with timezone guessing) - strong signal
    3. Position proximity (XYZ distance) - good tiebreaker
    4. Session duration match (uptime) - weak signal

    Returns the best overall match, not just first match.
    """
    from datetime import timezone, timedelta
    import math

    # Parse all dumps first
    candidates = []
    for dump_file in dump_files:
        try:
            dump = ServerDumpParser.parse(str(dump_file))
            candidates.append((dump_file, dump))
        except Exception:
            continue

    if not candidates:
        return None

    # Score each candidate
    scored = []
    for dump_file, dump in candidates:
        score = 0.0
        reasons = []

        # 1. Player name match (worth a lot if we have it)
        if player_name:
            filename = dump_file.name.lower()
            if player_name.lower() in filename:
                score += 100
                reasons.append("player_match")
            # Also check playerName in dump itself
            if dump.player_name and player_name.lower() == dump.player_name.lower():
                score += 100
                reasons.append("player_exact")

        # 2. Timestamp proximity (try multiple timezone offsets)
        crash_ts = crash.timestamp
        dump_ts = dump.disconnect_time

        # Make both timezone-naive
        crash_ts_naive = crash_ts.replace(tzinfo=None) if crash_ts.tzinfo else crash_ts
        dump_ts_naive = dump_ts.replace(tzinfo=None) if dump_ts.tzinfo else dump_ts

        best_time_diff = timedelta(hours=24)  # Start with worst case
        for offset_hours in [0, -5, -6, -7, -8, 5, 6, 7, 8, -4, 4, 1, -1]:
            adjusted = crash_ts_naive + timedelta(hours=offset_hours)
            diff = abs(dump_ts_naive - adjusted)
            if diff < best_time_diff:
                best_time_diff = diff

        # Score based on time proximity (max 50 points, decays with distance)
        time_seconds = best_time_diff.total_seconds()
        if time_seconds < 120:  # Within 2 minutes - great match
            score += 50
            reasons.append(f"time_exact({int(time_seconds)}s)")
        elif time_seconds < 300:  # Within 5 minutes - good
            score += 40
            reasons.append(f"time_close({int(time_seconds)}s)")
        elif time_seconds < 600:  # Within 10 minutes - okay
            score += 20
            reasons.append(f"time_fuzzy({int(time_seconds)}s)")

        # 3. Position proximity (if both have position data)
        if crash.position and dump.position:
            crash_pos = crash.position
            dump_pos = dump.position

            # Skip if dump position is 0,0,0 (not set)
            if not (dump_pos[0] == 0 and dump_pos[1] == 0 and dump_pos[2] == 0):
                distance = math.sqrt(
                    (crash_pos[0] - dump_pos[0]) ** 2 +
                    (crash_pos[1] - dump_pos[1]) ** 2 +
                    (crash_pos[2] - dump_pos[2]) ** 2
                )

                # Score based on distance (max 30 points)
                if distance < 50:  # Very close
                    score += 30
                    reasons.append(f"pos_exact({int(distance)})")
                elif distance < 200:  # Same area
                    score += 20
                    reasons.append(f"pos_close({int(distance)})")
                elif distance < 1000:  # Same region
                    score += 10
                    reasons.append(f"pos_region({int(distance)})")

        # 4. Session duration match (uptime)
        if crash.game_uptime_seconds and dump.session_duration_ms:
            crash_uptime = crash.game_uptime_seconds
            dump_uptime = dump.session_duration_ms // 1000

            uptime_diff = abs(crash_uptime - dump_uptime)
            if uptime_diff < 30:  # Within 30 seconds
                score += 20
                reasons.append(f"uptime_match({uptime_diff}s)")
            elif uptime_diff < 120:  # Within 2 minutes
                score += 10
                reasons.append(f"uptime_close({uptime_diff}s)")

        scored.append((score, reasons, dump_file, dump))

    # Sort by score descending
    scored.sort(key=lambda x: x[0], reverse=True)

    # Return best match if it has a reasonable score
    if scored:
        best_score, best_reasons, best_file, best_dump = scored[0]

        # Require at least some signal (player match OR time+something else)
        if best_score >= 40:
            return best_dump

        # If we have a player name and got any match, use it
        if player_name and best_score > 0:
            return best_dump

    return None


def _find_matching_dump_verbose(crash, dump_files, player_name: Optional[str] = None):
    """
    Same as _find_matching_dump but also returns scoring info for display.
    Returns: (best_dump, [(score, reasons, filename), ...])
    """
    from datetime import timezone, timedelta
    import math

    # Parse all dumps first
    candidates = []
    for dump_file in dump_files:
        try:
            dump = ServerDumpParser.parse(str(dump_file))
            candidates.append((dump_file, dump))
        except Exception:
            continue

    if not candidates:
        return None, []

    # Score each candidate
    scored = []
    for dump_file, dump in candidates:
        score = 0.0
        reasons = []

        # 1. Player name match
        if player_name:
            filename = dump_file.name.lower()
            if player_name.lower() in filename:
                score += 100
                reasons.append("player_file")
            if dump.player_name and player_name.lower() == dump.player_name.lower():
                score += 100
                reasons.append("player_exact")

        # 2. Timestamp proximity
        crash_ts = crash.timestamp
        dump_ts = dump.disconnect_time

        crash_ts_naive = crash_ts.replace(tzinfo=None) if crash_ts.tzinfo else crash_ts
        dump_ts_naive = dump_ts.replace(tzinfo=None) if dump_ts.tzinfo else dump_ts

        best_time_diff = timedelta(hours=24)
        for offset_hours in [0, -5, -6, -7, -8, 5, 6, 7, 8, -4, 4, 1, -1]:
            adjusted = crash_ts_naive + timedelta(hours=offset_hours)
            diff = abs(dump_ts_naive - adjusted)
            if diff < best_time_diff:
                best_time_diff = diff

        time_seconds = best_time_diff.total_seconds()
        if time_seconds < 120:
            score += 50
            reasons.append(f"time<2m")
        elif time_seconds < 300:
            score += 40
            reasons.append(f"time<5m")
        elif time_seconds < 600:
            score += 20
            reasons.append(f"time<10m")

        # 3. Position proximity
        if crash.position and dump.position:
            crash_pos = crash.position
            dump_pos = dump.position

            if not (dump_pos[0] == 0 and dump_pos[1] == 0 and dump_pos[2] == 0):
                distance = math.sqrt(
                    (crash_pos[0] - dump_pos[0]) ** 2 +
                    (crash_pos[1] - dump_pos[1]) ** 2 +
                    (crash_pos[2] - dump_pos[2]) ** 2
                )

                if distance < 50:
                    score += 30
                    reasons.append(f"pos<50")
                elif distance < 200:
                    score += 20
                    reasons.append(f"pos<200")
                elif distance < 1000:
                    score += 10
                    reasons.append(f"pos<1k")

        # 4. Session duration match
        if crash.game_uptime_seconds and dump.session_duration_ms:
            crash_uptime = crash.game_uptime_seconds
            dump_uptime = dump.session_duration_ms // 1000

            uptime_diff = abs(crash_uptime - dump_uptime)
            if uptime_diff < 30:
                score += 20
                reasons.append(f"uptime<30s")
            elif uptime_diff < 120:
                score += 10
                reasons.append(f"uptime<2m")

        scored.append((score, reasons, dump_file, dump))

    # Sort by score descending
    scored.sort(key=lambda x: x[0], reverse=True)

    # Build match info for display
    match_info = [(s, r, f.name) for s, r, f, d in scored if s > 0]

    # Return best match if reasonable
    if scored:
        best_score, best_reasons, best_file, best_dump = scored[0]

        if best_score >= 40:
            return best_dump, match_info

        if player_name and best_score > 0:
            return best_dump, match_info

    return None, match_info


def _extract_player_from_filename(filename: str) -> Optional[str]:
    """
    Extract player name from crash log filename.

    Expected format: {player}_planetside_crash.log or {player}_crash.log
    Example: admin_planetside_crash.log -> admin
    """
    import re
    name = Path(filename).stem.lower()

    # Try common patterns
    patterns = [
        r'^([a-z0-9_]+?)_planetside_crash',  # admin_planetside_crash
        r'^([a-z0-9_]+?)_crash',              # admin_crash
        r'^([a-z0-9_]+?)_ps_crash',           # admin_ps_crash
    ]

    for pattern in patterns:
        match = re.match(pattern, name, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


@cli.command()
@click.option('--client-log', required=True, type=click.Path(exists=True),
              help='Path to planetside_crash.log (optionally named {player}_planetside_crash.log)')
@click.option('--dumps-dir', required=True, type=click.Path(exists=True, file_okay=False),
              help='Directory containing server packet dumps')
@click.option('--player', type=str, default=None,
              help='Player name (auto-detected from filename if named {player}_planetside_crash.log)')
@click.option('--db', default='crashes.db', type=click.Path(),
              help='Path to SQLite database (default: crashes.db)')
@click.option('--window', default=100, type=int,
              help='Number of trailing packets to analyze (default: 100)')
def analyze(client_log: str, dumps_dir: str, player: Optional[str], db: str, window: int):
    """
    One-shot analysis: find matching dump, ingest, and investigate.

    Naming convention for auto-matching:
        Rename crash log to: {player}_planetside_crash.log
        Example: admin_planetside_crash.log

    Server dumps are named: packet_dump_{player}_{timestamp}.json
    The tool will match on player name, then refine by timestamp.

    Example:
        crash_analyzer analyze --client-log admin_planetside_crash.log --dumps-dir ../crash_dumps/
    """
    click.echo("=" * 70)
    click.echo("CRASH ANALYZER - AUTO ANALYZE")
    click.echo("=" * 70)

    # Try to extract player from filename if not provided
    if not player:
        player = _extract_player_from_filename(client_log)
        if player:
            click.echo(f"\nAuto-detected player from filename: {player}")
        else:
            click.echo("\nNo player name in filename - will use fuzzy timestamp matching")

    # Parse crash log
    click.echo(f"\nParsing crash log: {client_log}")
    try:
        crash = CrashLogParser.parse(client_log)
    except Exception as e:
        click.echo(f"ERROR: Failed to parse crash log: {e}", err=True)
        sys.exit(1)

    click.echo(f"  Signature:  {crash.signature}")
    click.echo(f"  Timestamp:  {crash.timestamp}")
    click.echo(f"  Map:        {crash.map_name}")
    click.echo(f"  Position:   ({crash.position[0]:.2f}, {crash.position[1]:.2f}, {crash.position[2]:.2f})")
    click.echo(f"  Uptime:     {crash.game_uptime_seconds}s")

    # Find matching dump
    dumps_path = Path(dumps_dir)
    dump_files = list(dumps_path.glob('**/*.json'))
    click.echo(f"\nSearching {len(dump_files)} dumps in {dumps_dir}...")

    dump, match_info = _find_matching_dump_verbose(crash, dump_files, player)

    if match_info:
        click.echo(f"\nMatch scoring (top candidates):")
        for score, reasons, filename in match_info[:3]:  # Show top 3
            click.echo(f"  {score:5.0f} pts - {filename} [{', '.join(reasons)}]")

    if dump:
        click.echo(click.style(f"\n  MATCHED: {dump.dump_path}", fg='green'))
        click.echo(f"  Player:     {dump.player_name or 'Unknown'}")
        click.echo(f"  Zone:       {dump.zone or 'Unknown'}")
        click.echo(f"  Packets:    {len(dump.packets)}")
        click.echo(f"  Duration:   {dump.session_duration_ms // 1000}s")
    else:
        click.echo(click.style("\n  NO MATCHING DUMP FOUND", fg='yellow'))
        click.echo("  Will store crash log only (no packet analysis possible)")

    # Store in database
    click.echo(f"\nStoring in database: {db}")
    database = CrashDatabase(db)
    try:
        crash_id = database.ingest_crash(crash, dump)
        click.echo(f"  Stored as crash_id: {crash_id}")

        sig_count = database.get_signature_count(crash.signature)
        click.echo(f"  This signature has been seen {sig_count} time(s)")

    finally:
        database.close()

    # Auto-investigate if we have packet data
    if dump and len(dump.packets) > 0:
        click.echo("\n" + "=" * 70)
        click.echo("PATTERN ANALYSIS")
        click.echo("=" * 70)

        database = CrashDatabase(db)
        try:
            results = analyze_signature_patterns(database, crash.signature, window_size=window)

            if 'error' not in results:
                click.echo(f"\nSignature: {results['signature']}")
                click.echo(f"Total crashes with this signature: {results['total_crashes']}")
                click.echo(f"Analysis window: last {results['window_size']} packets")

                if results['common_packets']:
                    click.echo("\nPackets appearing in 50%+ of crashes:")
                    for pkt in results['common_packets'][:10]:  # Top 10
                        click.echo(f"  {pkt['type']:40} - {pkt['appearances']}/{results['total_crashes']} ({pkt['rate']*100:.1f}%)")

                if results['suspicious_packets']:
                    click.echo(click.style("\nSUSPICIOUS PACKETS (high frequency):", fg='red', bold=True))
                    for pkt in results['suspicious_packets']:
                        click.echo(click.style(f"  {pkt['type']:40} - avg {pkt['avg_per_crash']:.1f} per crash", fg='red'))
                else:
                    click.echo("\nNo suspicious packet patterns detected")

        finally:
            database.close()

    click.echo("\n" + "=" * 70)
    click.echo("ANALYSIS COMPLETE")
    click.echo("=" * 70)


@cli.command()
@click.argument('signature')
@click.option('--db', default='crashes.db', type=click.Path(exists=True),
              help='Path to SQLite database (default: crashes.db)')
@click.option('--window', default=100, type=int,
              help='Number of trailing packets to analyze (default: 100)')
def investigate(signature: str, db: str, window: int):
    """
    Analyze patterns for crashes with a specific signature.

    Example:
        crash_analyzer investigate 0x008EED30_0x00000040
    """
    click.echo("=" * 70)
    click.echo("CRASH PATTERN ANALYSIS")
    click.echo("=" * 70)

    database = CrashDatabase(db)
    try:
        results = analyze_signature_patterns(database, signature, window_size=window)

        if 'error' in results:
            click.echo(f"\nERROR: {results['error']}", err=True)
            sys.exit(1)

        # Header
        click.echo(f"\nSignature: {results['signature']}")
        click.echo(f"Total crashes: {results['total_crashes']}")
        click.echo(f"Unique players: {results['unique_players']}")
        click.echo(f"Analysis window: last {results['window_size']} packets")

        # Map distribution
        if results['maps']:
            click.echo("\nMost common maps:")
            for map_name, count in results['maps'].items():
                rate = (count / results['total_crashes']) * 100
                click.echo(f"  {map_name:12} - {count:3} crashes ({rate:5.1f}%)")

        # Common packets (appearing in 50%+ of crashes)
        if results['common_packets']:
            click.echo("\nPackets appearing in 50%+ of crashes:")
            for pkt in results['common_packets']:
                click.echo(f"  {pkt['type']:40} - {pkt['appearances']:3}/{results['total_crashes']} crashes ({pkt['rate']*100:5.1f}%)")

        # Suspicious packets (high frequency)
        if results['suspicious_packets']:
            click.echo("\nSuspicious packets (high frequency in trailing window):")
            for pkt in results['suspicious_packets']:
                click.echo(f"  {pkt['type']:40} - avg {pkt['avg_per_crash']:6.1f} per crash (total: {pkt['total_count']})")
        else:
            click.echo("\nNo suspicious packet patterns detected")

        click.echo("\n" + "=" * 70)

    finally:
        database.close()


@cli.command()
@click.option('--db', default='crashes.db', type=click.Path(exists=True),
              help='Path to SQLite database (default: crashes.db)')
def stats(db: str):
    """
    Show database statistics.

    Example:
        crash_analyzer stats
    """
    click.echo("=" * 70)
    click.echo("CRASH DATABASE STATISTICS")
    click.echo("=" * 70)

    database = CrashDatabase(db)
    try:
        stats_data = database.get_stats()

        click.echo(f"\nTotal crashes:      {stats_data['total_crashes']}")
        click.echo(f"Unique signatures:  {stats_data['unique_signatures']}")
        click.echo(f"Matched to dumps:   {stats_data['matched_crashes']}")
        click.echo(f"Unmatched:          {stats_data['unmatched_crashes']}")

        if stats_data['first_crash'] and stats_data['last_crash']:
            click.echo(f"\nDate range:")
            click.echo(f"  First crash:  {stats_data['first_crash']}")
            click.echo(f"  Last crash:   {stats_data['last_crash']}")

        if stats_data['top_signatures']:
            click.echo(f"\nTop 10 signatures by frequency:")
            for sig in stats_data['top_signatures']:
                click.echo(f"  {sig['signature']:30} - {sig['crash_count']:3} crashes")

        click.echo("\n" + "=" * 70)

    finally:
        database.close()


if __name__ == '__main__':
    cli()
