#!/usr/bin/env bash
#
# capture-baseline.sh
#
# Captures a performance baseline snapshot on a RHEL host, using only
# default OS tools (falls back gracefully if sysstat isn't installed).
# Intended for pre-/post-migration comparison — run once before cutover
# and once after, then diff the two log files.
#
# Usage:
#   ./capture-baseline.sh [label]
#
#   label   Optional tag appended to the output filename, e.g. "pre" or
#           "post". Defaults to "baseline".
#
# Output:
#   <hostname>_<label>_<timestamp>.log in the current directory.

set -uo pipefail

LABEL="${1:-baseline}"
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || hostname)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTFILE="${HOSTNAME_SHORT}_${LABEL}_${TIMESTAMP}.log"

# Fixed sampling so pre/post runs are directly comparable
SAMPLE_INTERVAL=1
SAMPLE_COUNT=5

section() {
    echo ""
    echo "==================================================================="
    echo "== $1"
    echo "==================================================================="
}

run() {
    # run <description> <command...>
    local desc="$1"
    shift
    echo ""
    echo "--- ${desc} ---"
    if command -v "$1" >/dev/null 2>&1; then
        "$@" 2>&1
    else
        echo "[skipped: $1 not available]"
    fi
}

{
    echo "Baseline capture: ${LABEL}"
    echo "Host:             $(hostname -f 2>/dev/null || hostname)"
    echo "Date:             $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
    echo "Kernel:           $(uname -r)"
    echo "OS:               $(cat /etc/redhat-release 2>/dev/null || echo unknown)"
    echo "Uptime:           $(uptime -p 2>/dev/null || uptime)"

    section "CPU"
    run "load average"        cat /proc/loadavg
    run "top snapshot"        top -bn1
    run "per-core (mpstat)"   mpstat -P ALL "${SAMPLE_INTERVAL}" "${SAMPLE_COUNT}"
    run "vmstat"               vmstat "${SAMPLE_INTERVAL}" "${SAMPLE_COUNT}"

    section "MEMORY"
    run "free -h"             free -h
    run "/proc/meminfo"       cat /proc/meminfo

    section "DISK"
    run "df -h"                df -h
    run "iostat -xz"           iostat -xz "${SAMPLE_INTERVAL}" "${SAMPLE_COUNT}"
    run "/proc/diskstats"      cat /proc/diskstats

    section "NETWORK"
    run "interface counters"   ip -s link
    run "socket summary"       ss -s
    run "/proc/net/dev"        cat /proc/net/dev

    # ethtool needs an interface name — report per active interface
    echo ""
    echo "--- ethtool per interface ---"
    if command -v ethtool >/dev/null 2>&1; then
        for iface in $(ls /sys/class/net | grep -v lo); do
            echo ""
            echo "[${iface}]"
            ethtool "${iface}" 2>&1
        done
    else
        echo "[skipped: ethtool not available]"
    fi

    section "SYSTEM-WIDE (sar, if present)"
    run "sar -A"                sar -A "${SAMPLE_INTERVAL}" "${SAMPLE_COUNT}"

    echo ""
    echo "=== capture complete ==="

} | tee "${OUTFILE}"

echo ""
echo "Saved to: ${OUTFILE}"
