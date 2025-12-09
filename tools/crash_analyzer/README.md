# PlanetSide Crash Analyzer

A CLI tool for analyzing PlanetSide 1 client crashes by correlating client crash logs with server packet dumps.

## Overview

When a PlanetSide 1 client crashes, it creates `planetside_crash.log`. When the PSForever server detects an unexpected disconnect (not graceful logout), it dumps the last ~5 minutes of packets sent to that client as JSON.

This tool correlates the two:
- **Client crash log** tells us *where* in the client code it crashed
- **Server packet dump** tells us *what packets were sent* before the crash

By analyzing multiple crashes with the same signature, we can identify which packets (or packet patterns) are likely causing the crash.

## Requirements

- Python 3.7+
- Dependencies in `requirements.txt`

## Installation

```bash
cd tools/crash_analyzer/

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

```bash
# Make executable
chmod +x crash_analyzer.py

# Show help
./crash_analyzer.py --help

# One-shot analysis: ingest crash + matching dump
./crash_analyzer.py ingest \
  --client-log /path/to/planetside_crash.log \
  --server-dump /path/to/packet_dump_PlayerName_timestamp.json

# View database stats
./crash_analyzer.py stats

# Investigate a specific crash signature
./crash_analyzer.py investigate 0x008EED30_0x00000040
```

## Commands

### `ingest` - Analyze a Single Crash

```bash
./crash_analyzer.py ingest \
  --client-log path/to/planetside_crash.log \
  --server-dump path/to/packet_dump.json
```

- Parses both files
- Attempts to correlate by timestamp, position, zone
- Stores in SQLite database (`crashes.db`)
- Shows how many times this crash signature has been seen

### `ingest-dir` - Bulk Import

```bash
./crash_analyzer.py ingest-dir \
  --client-logs ./crash_logs/ \
  --server-dumps ./crash_dumps/
```

- Processes all `.log` and `.json` files in directories
- Attempts to match each crash to its corresponding dump
- Reports matched vs unmatched

### `stats` - Database Overview

```bash
./crash_analyzer.py stats
```

Shows:
- Total crashes analyzed
- Unique crash signatures
- Match rate (crashes with server dumps)
- Top 10 signatures by frequency

### `investigate` - Pattern Analysis

```bash
./crash_analyzer.py investigate 0x008EED30_0x00000040
```

Shows:
- All crashes with this signature
- Common maps where it occurs
- Packets appearing in 50%+ of crashes (suspects)
- Recommendations for investigation

## How It Works

### Crash Signatures

Each crash has a "signature" identifying where in the client code it crashed:

```
Format: {exception_address}_{reading_address}
Example: 0x008EED30_0x00000040
```

Same signature = same bug. This allows clustering crashes to find patterns.

### Correlation Logic

The analyzer matches crash logs to server dumps by:

1. **Timestamp** - within 60 seconds
2. **Session duration** - within 30 seconds tolerance
3. **Position** - within 1000 game units
4. **Zone/map** - cross-referenced via map ID mapping

### What to Look For

When investigating a signature:

- **Packets in 100% of crashes** - Very likely the cause
- **High frequency unusual packets** - Potential spam attacks
- **Map-specific crashes** - Zone transition issues
- **Vehicle-related packets** - Mount/dismount state bugs
- **GenericObjectActionMessage** - Known to cause crashes with certain codes

## Server Configuration

The packet trail logger is configured in `application.conf`:

```hocon
packet-trail-logger {
  enabled = yes
  buffer-size = 6000        # ~5 minutes at 20 packets/sec
  output-directory = "./crash_dumps"
}
```

Dumps are only created on **unexpected disconnects** (keepalive timeout, errors). Graceful logouts do not create dumps.

## Example Workflow

1. **Client crashes** - Player gets `planetside_crash.log`
2. **Server detects disconnect** - Creates `crash_dumps/packet_dump_PlayerName_timestamp.json`
3. **Admin collects both files** - Via Discord, email, etc.
4. **Ingest into analyzer**:
   ```bash
   ./crash_analyzer.py ingest \
     --client-log planetside_crash.log \
     --server-dump packet_dump_PlayerName_*.json
   ```
5. **Check if it's a known issue**:
   ```bash
   ./crash_analyzer.py stats
   ```
6. **Investigate the signature**:
   ```bash
   ./crash_analyzer.py investigate <signature>
   ```

## File Locations

- **Client crash log**: `<PlanetSide install>/planetside_crash.log`
- **Server packet dumps**: `<server>/crash_dumps/packet_dump_*.json`
- **Analyzer database**: `crashes.db` (created in current directory)

## Troubleshooting

**"No matching dump found"**
- Client and server clocks may be out of sync
- Crash happened before packet logger started recording
- Was actually a graceful logout (no dump created)

**"Could not extract X from crash log"**
- Different Wine/native versions may format logs differently
- Check log file manually, report format issues

**"Database locked"**
- Close other instances of the analyzer
- Check if `crashes.db` is open elsewhere
