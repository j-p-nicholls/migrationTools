#!/usr/bin/env bash
#
# poll-metrics.sh
#
# Polls CPU, memory, and disk activity on a RHEL host over a specified
# duration and writes the results to a CSV. Uses only /proc data — no
# extra packages required.
#
# Metrics:
#   CPU %     - total processor time in use over the sample interval
#               (100 - idle), from /proc/stat
#   Memory %  - committed memory as a percentage of the commit limit
#               (Committed_AS / CommitLimit), from /proc/meminfo
#   Disk %    - disk time in use over the sample interval, summed across
#               all block devices ((delta io_ticks / interval_ms) * 100),
#               from /proc/diskstats
#
# Usage:
#   ./poll-metrics.sh <duration_minutes> [interval_seconds] [outfile]
#
#   duration_minutes   Total time to poll for, in minutes (e.g. 5, 30)
#   interval_seconds   Time between samples, in seconds. Default: 5
#   outfile            CSV output path. Default: <hostname>_metrics_<timestamp>.csv
#
# Examples:
#   ./poll-metrics.sh 5              # 5 minutes, 5s samples
#   ./poll-metrics.sh 30 10          # 30 minutes, 10s samples
#   ./poll-metrics.sh 15 5 out.csv   # 15 minutes, 5s samples, custom filename

set -uo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <duration_minutes> [interval_seconds] [outfile]" >&2
    exit 1
fi

DURATION_MIN="$1"
INTERVAL_SEC="${2:-5}"
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || hostname)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTFILE="${3:-${HOSTNAME_SHORT}_metrics_${TIMESTAMP}.csv}"

TOTAL_SECONDS=$(awk -v m="${DURATION_MIN}" 'BEGIN{printf "%d", m*60}')
SAMPLE_COUNT=$(awk -v t="${TOTAL_SECONDS}" -v i="${INTERVAL_SEC}" 'BEGIN{printf "%d", t/i}')

if [ "${SAMPLE_COUNT}" -lt 1 ]; then
    echo "Duration too short for the given interval." >&2
    exit 1
fi

# --- helpers -----------------------------------------------------------

read_cpu_total_idle() {
    # Aggregate 'cpu' line: user nice system idle iowait irq softirq steal guest guest_nice
    awk '/^cpu /{
        idle = $5 + $6
        total = $2+$3+$4+$5+$6+$7+$8+$9+$10
        printf "%s %s", total, idle
    }' /proc/stat
}

read_disk_io_ticks() {
    # Sum field 13 (io_ticks, ms spent doing I/O) across real block devices,
    # excluding loop/ram/dm partitions-of-partitions noise where possible.
    awk '{
        dev = $3
        if (dev !~ /^(loop|ram|sr)/) {
            sum += $13
        }
    } END { printf "%d", sum+0 }' /proc/diskstats
}

read_committed_mem_pct() {
    awk '
        /^Committed_AS:/ { committed = $2 }
        /^CommitLimit:/  { limit = $2 }
        END {
            if (limit > 0) {
                printf "%.2f", (committed/limit)*100
            } else {
                printf "0.00"
            }
        }
    ' /proc/meminfo
}

# --- main loop -----------------------------------------------------------

echo "Timestamp,CPU_Usage_Percent,Memory_Committed_Percent,Disk_Time_Percent" | tee "${OUTFILE}"

echo "Polling ${HOSTNAME_SHORT} for ${DURATION_MIN} minute(s), ${INTERVAL_SEC}s interval, ${SAMPLE_COUNT} sample(s)..." >&2
echo "Also saving a copy on this host at: ${OUTFILE}" >&2

for i in $(seq 1 "${SAMPLE_COUNT}"); do
    read -r cpu_total_1 cpu_idle_1 <<< "$(read_cpu_total_idle)"
    disk_ticks_1=$(read_disk_io_ticks)

    sleep "${INTERVAL_SEC}"

    read -r cpu_total_2 cpu_idle_2 <<< "$(read_cpu_total_idle)"
    disk_ticks_2=$(read_disk_io_ticks)

    cpu_pct=$(awk -v t1="${cpu_total_1}" -v t2="${cpu_total_2}" -v i1="${cpu_idle_1}" -v i2="${cpu_idle_2}" '
        BEGIN {
            dt = t2 - t1
            di = i2 - i1
            if (dt > 0) {
                printf "%.2f", (1 - (di/dt)) * 100
            } else {
                printf "0.00"
            }
        }
    ')

    disk_pct=$(awk -v d1="${disk_ticks_1}" -v d2="${disk_ticks_2}" -v interval_ms="$((INTERVAL_SEC * 1000))" '
        BEGIN {
            dd = d2 - d1
            pct = (dd/interval_ms) * 100
            if (pct > 100) pct = 100
            if (pct < 0) pct = 0
            printf "%.2f", pct
        }
    ')

    mem_pct=$(read_committed_mem_pct)

    ts=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

    echo "${ts},${cpu_pct},${mem_pct},${disk_pct}" | tee -a "${OUTFILE}"
done

echo "" >&2
echo "Done. Local copy on this host: ${OUTFILE}" >&2
