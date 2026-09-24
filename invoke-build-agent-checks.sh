#!/usr/bin/env bash
#
# invoke-build-agent-checks.sh
#
# Linux/RHEL equivalent of Invoke-BuildAgentChecks.ps1 — validates a
# DevOps build/CI agent server post-migration (VMware -> Azure).
# Uses only default OS tools (no assumed extra packages), consistent with
# capture-baseline.sh / poll-metrics.sh.
#
# Outputs structured JSON plus a dark-themed PASS/WARN/FAIL HTML report,
# matching the Windows script's format.
#
# Usage:
#   ./invoke-build-agent-checks.sh -p Baseline -o /opt/migration-checks
#   ./invoke-build-agent-checks.sh -p Migrated -o /opt/migration-checks \
#       -b /opt/migration-checks/BuildAgentChecks_Baseline_<host>.json
#
# Options:
#   -p  Phase: Baseline | Migrated   (required)
#   -o  Output directory             (default: ./BuildAgentChecks)
#   -b  Baseline JSON path (only used when -p Migrated)
#   -t  Timeout seconds for network checks (default: 10)
#   -r  Comma-separated list of registry URLs to test
#       (default: github.com,api.nuget.org,registry.npmjs.org,pypi.org)

set -u

PHASE=""
OUTDIR="./BuildAgentChecks"
BASELINE_JSON=""
TIMEOUT=10
REGISTRY_URLS="https://github.com,https://api.nuget.org/v3/index.json,https://registry.npmjs.org,https://pypi.org"
REQUIRED_TOOLS="git dotnet node npm mvn python3 docker java"

while getopts "p:o:b:t:r:h" opt; do
    case "$opt" in
        p) PHASE="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        b) BASELINE_JSON="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        r) REGISTRY_URLS="$OPTARG" ;;
        h)
            grep '^#' "$0" | sed 's/^#//'
            exit 0
            ;;
        *) echo "Unknown option"; exit 1 ;;
    esac
done

if [[ "$PHASE" != "Baseline" && "$PHASE" != "Migrated" ]]; then
    echo "ERROR: -p must be 'Baseline' or 'Migrated'"
    exit 1
fi

HOSTNAME_VAL="$(hostname)"
TIMESTAMP="$(date '+%Y-%m-%dT%H:%M:%S')"
mkdir -p "$OUTDIR"

JSON_PATH="$OUTDIR/BuildAgentChecks_${PHASE}_${HOSTNAME_VAL}.json"
HTML_PATH="$OUTDIR/BuildAgentChecks_${PHASE}_${HOSTNAME_VAL}.html"
RESULTS_TMP="$(mktemp)"
TOOLVER_TMP="$(mktemp)"
AGENT_ACCOUNTS_FILE="$(mktemp)"
trap 'rm -f "$RESULTS_TMP" "$TOOLVER_TMP" "$AGENT_ACCOUNTS_FILE"' EXIT

echo "=== Build Agent Checks: $HOSTNAME_VAL [$PHASE] ==="

# ---- helpers -----------------------------------------------------------

# Minimal JSON string escaper (handles backslash, quote, newline, tab)
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# add_result <category> <check> <status PASS|WARN|FAIL|INFO> <detail>
add_result() {
    local category="$1" check="$2" status="$3" detail="$4"
    local ts
    ts="$(date '+%Y-%m-%dT%H:%M:%S')"
    printf '{"Category":"%s","Check":"%s","Status":"%s","Detail":"%s","Timestamp":"%s"}\n' \
        "$(json_escape "$category")" "$(json_escape "$check")" "$status" \
        "$(json_escape "$detail")" "$ts" >> "$RESULTS_TMP"

    case "$status" in
        PASS) c="\033[32m" ;;
        WARN) c="\033[33m" ;;
        FAIL) c="\033[31m" ;;
        *)    c="\033[90m" ;;
    esac
    printf "  [${c}%s\033[0m] %s / %s: %s\n" "$status" "$category" "$check" "$detail"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---- 1. Orchestrator / agent registration -------------------------------
echo -e "\n[1/5] Orchestrator agent registration..."

# Track the account(s) each detected agent service actually runs as, so
# later checks (config files) look in the right home directory rather
# than whichever account is running this script (SSH/sudo user).
add_agent_account() {
    local acct="$1"
    [[ -n "$acct" ]] && echo "$acct" >> "$AGENT_ACCOUNTS_FILE"
}

# systemd exposes the configured run-as account via `User=` in the unit;
# an empty value means it defaults to root.
get_unit_user() {
    local unit="$1"
    local u
    u="$(systemctl show "$unit" -p User --value 2>/dev/null)"
    [[ -z "$u" ]] && u="root"
    echo "$u"
}

# Azure DevOps agent (self-hosted Linux agent runs as a systemd service).
# The real-world unit name is typically "vsts.agent.<pool>.<agentname>.service"
# (dotted, with pool/agent name embedded) — match loosely on "vsts" + "agent"
# regardless of separator, rather than the literal string "vstsagent".
ADO_UNITS="$(systemctl list-units --type=service --all 2>/dev/null | grep -iE 'vsts.{0,3}agent' | awk '{print $1}')"
if [[ -n "$ADO_UNITS" ]]; then
    while IFS= read -r unit; do
        state="$(systemctl is-active "$unit" 2>/dev/null)"
        status="FAIL"; [[ "$state" == "active" ]] && status="PASS"
        runas="$(get_unit_user "$unit")"
        add_result "AgentRegistration" "ADO Agent Service: $unit" "$status" "systemd state: $state, RunsAs: $runas"
        add_agent_account "$runas"
    done <<< "$ADO_UNITS"
else
    add_result "AgentRegistration" "Azure DevOps Agent Service" "INFO" "No vsts.agent.* systemd unit found"
fi

# Jenkins agent/node (jenkins service, or inbound-agent/swarm-client process)
JENKINS_UNIT="$(systemctl list-units --type=service --all 2>/dev/null | grep -i 'jenkins' | awk '{print $1}')"
if [[ -n "$JENKINS_UNIT" ]]; then
    while IFS= read -r unit; do
        state="$(systemctl is-active "$unit" 2>/dev/null)"
        status="FAIL"; [[ "$state" == "active" ]] && status="PASS"
        runas="$(get_unit_user "$unit")"
        add_result "AgentRegistration" "Jenkins Service: $unit" "$status" "systemd state: $state, RunsAs: $runas"
        add_agent_account "$runas"
    done <<< "$JENKINS_UNIT"
elif pgrep -f 'agent.jar|swarm-client' >/dev/null 2>&1; then
    # No systemd unit — fall back to the actual owning user of the running process
    jenkins_pid="$(pgrep -f 'agent.jar|swarm-client' | head -n1)"
    runas="$(ps -o user= -p "$jenkins_pid" 2>/dev/null | tr -d ' ')"
    add_result "AgentRegistration" "Jenkins Agent Process" "PASS" "agent.jar/swarm-client process running, RunsAs: ${runas:-unknown}"
    add_agent_account "$runas"
else
    add_result "AgentRegistration" "Jenkins Agent" "INFO" "No jenkins systemd unit or agent.jar process found"
fi

# GitLab Runner
if have_cmd gitlab-runner; then
    state="$(systemctl is-active gitlab-runner 2>/dev/null)"
    status="FAIL"; [[ "$state" == "active" ]] && status="PASS"
    if systemctl list-units --type=service --all 2>/dev/null | grep -q 'gitlab-runner'; then
        runas="$(get_unit_user gitlab-runner)"
    else
        gl_pid="$(pgrep -f 'gitlab-runner run' | head -n1)"
        runas="$(ps -o user= -p "$gl_pid" 2>/dev/null | tr -d ' ')"
    fi
    add_result "AgentRegistration" "GitLab Runner Service" "$status" "systemd state: $state, RunsAs: ${runas:-unknown}"
    add_agent_account "$runas"

    runner_list="$(gitlab-runner list 2>&1)"
    add_result "AgentRegistration" "GitLab Runner Registration List" "INFO" "$runner_list"
else
    add_result "AgentRegistration" "GitLab Runner" "INFO" "gitlab-runner binary not found"
fi

if [[ -z "$ADO_UNITS" && -z "$JENKINS_UNIT" && ! $(pgrep -f 'agent.jar|swarm-client') && ! $(have_cmd gitlab-runner) ]]; then
    add_result "AgentRegistration" "Orchestrator Detection" "WARN" "No known orchestrator agent (ADO/Jenkins/GitLab) detected — verify manually"
fi

# Dedupe agent accounts
AGENT_ACCOUNTS="$(sort -u "$AGENT_ACCOUNTS_FILE" 2>/dev/null)"

# Resolve an account's home directory via getent (works for both local
# and directory-backed — e.g. SSSD/LDAP — accounts, unlike trusting $HOME).
resolve_account_home() {
    local acct="$1"
    getent passwd "$acct" 2>/dev/null | cut -d: -f6
}


echo -e "\n[2/5] Toolchain version capture..."

declare -A TOOL_VERSIONS

get_version() {
    local tool="$1"
    case "$tool" in
        git)    git --version 2>&1 ;;
        dotnet) dotnet --version 2>&1 ;;
        node)   node --version 2>&1 ;;
        npm)    npm --version 2>&1 ;;
        mvn)    mvn --version 2>&1 | head -n1 ;;
        python3) python3 --version 2>&1 ;;
        docker) docker --version 2>&1 ;;
        java)   java -version 2>&1 | head -n1 ;;
        *)      "$tool" --version 2>&1 | head -n1 ;;
    esac
}

for tool in $REQUIRED_TOOLS; do
    if have_cmd "$tool"; then
        path="$(command -v "$tool")"
        ver="$(get_version "$tool")"
        TOOL_VERSIONS["$tool"]="$ver"
        printf '{"tool":"%s","path":"%s","version":"%s"}\n' \
            "$(json_escape "$tool")" "$(json_escape "$path")" "$(json_escape "$ver")" >> "$TOOLVER_TMP"
        add_result "Toolchain" "Tool: $tool" "PASS" "$ver ($path)"
    else
        TOOL_VERSIONS["$tool"]=""
        add_result "Toolchain" "Tool: $tool" "WARN" "Not found on PATH"
    fi
done

# ---- 3. Environment & config capture ------------------------------------
echo -e "\n[3/5] Environment and config capture..."

# NOTE: $PATH and the env vars below reflect the account running THIS
# script (typically your SSH/sudo session), which may differ from the
# build agent's own service account. Use the AgentServiceAccount checks
# below for what the agent process itself actually sees.
add_result "Environment" "Script Running As" "INFO" "$(whoami) (interactive/test account — see AgentServiceAccount checks below for the actual agent identity)"

PATH_COUNT="$(echo "$PATH" | tr ':' '\n' | grep -c .)"
add_result "Environment" "PATH Entry Count (current session)" "INFO" "$PATH_COUNT entries"

for var in JAVA_HOME DOTNET_ROOT NODE_ENV NPM_CONFIG_PREFIX PYTHONPATH MAVEN_HOME M2_HOME GOPATH GOROOT DOCKER_HOST; do
    if [[ -n "${!var:-}" ]]; then
        add_result "Environment" "EnvVar: $var" "INFO" "${!var}"
    fi
done

# Package manager config files — checked per detected agent service
# account, not the SSH/sudo session's own $HOME, since that's what the
# agent process actually reads from.
if [[ -z "$AGENT_ACCOUNTS" ]]; then
    add_result "Environment" "Agent Service Account Config Check" "WARN" \
        "No agent service account was identified in section 1 — skipping per-account config checks. Config files under your own \$HOME are NOT representative of the agent."
else
    while IFS= read -r account; do
        [[ -z "$account" ]] && continue
        acct_home="$(resolve_account_home "$account")"

        if [[ -z "$acct_home" ]]; then
            add_result "Environment" "Agent Service Account: $account" "WARN" \
                "Could not resolve a home directory via getent passwd — account may not exist locally (e.g. AD/SSSD lookup issue) or config lives elsewhere"
            continue
        fi

        add_result "Environment" "Agent Service Account: $account" "PASS" "Home: $acct_home"

        declare -A CONFIG_PATHS=(
            ["NuGet.Config"]="$acct_home/.nuget/NuGet/NuGet.Config"
            [".npmrc (user)"]="$acct_home/.npmrc"
            ["pip.conf"]="$acct_home/.config/pip/pip.conf"
            ["Maven settings"]="$acct_home/.m2/settings.xml"
        )
        for name in "${!CONFIG_PATHS[@]}"; do
            path="${CONFIG_PATHS[$name]}"
            # Reading another account's home may fail on permissions even
            # when running as root over some restrictive umask setups.
            if [[ -r "$path" ]]; then
                add_result "Environment" "[$account] Config present: $name" "PASS" "$path"
            elif [[ -e "$path" ]]; then
                add_result "Environment" "[$account] Config present: $name" "WARN" "Exists at $path but not readable by current user — re-run as root/sudo to confirm contents"
            else
                add_result "Environment" "[$account] Config present: $name" "INFO" "Not found at $path"
            fi
        done
    done <<< "$AGENT_ACCOUNTS"
fi

# ---- 4. Network reachability (source control / registries) --------------
echo -e "\n[4/5] Network reachability to source control / registries..."

IFS=',' read -ra URLS <<< "$REGISTRY_URLS"
for url in "${URLS[@]}"; do
    host="$(echo "$url" | sed -E 's#^https?://##' | cut -d/ -f1)"

    # DNS resolution
    if have_cmd getent && getent hosts "$host" >/dev/null 2>&1; then
        ip="$(getent hosts "$host" | awk '{print $1}' | head -n1)"
        add_result "NetworkReachability" "DNS resolution: $host" "PASS" "$ip"
    elif have_cmd host && host "$host" >/dev/null 2>&1; then
        add_result "NetworkReachability" "DNS resolution: $host" "PASS" "resolved via host(1)"
    else
        add_result "NetworkReachability" "DNS resolution: $host" "FAIL" "Could not resolve $host"
        continue
    fi

    # HTTPS reachability
    if have_cmd curl; then
        http_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" -I "$url" 2>/dev/null)"
        if [[ -n "$http_code" && "$http_code" != "000" ]]; then
            add_result "NetworkReachability" "HTTPS reachability: $host" "PASS" "HTTP $http_code"
        else
            add_result "NetworkReachability" "HTTPS reachability: $host" "FAIL" "curl: no response within ${TIMEOUT}s"
        fi
    elif have_cmd wget; then
        if wget -q --spider --timeout="$TIMEOUT" "$url" 2>/dev/null; then
            add_result "NetworkReachability" "HTTPS reachability: $host" "PASS" "wget spider succeeded"
        else
            add_result "NetworkReachability" "HTTPS reachability: $host" "FAIL" "wget: spider failed within ${TIMEOUT}s"
        fi
    else
        # Fall back to raw TCP/443 via /dev/tcp (bash builtin)
        if timeout "$TIMEOUT" bash -c "cat < /dev/null > /dev/tcp/$host/443" 2>/dev/null; then
            add_result "NetworkReachability" "HTTPS reachability: $host" "PASS" "TCP/443 connect succeeded (no curl/wget available)"
        else
            add_result "NetworkReachability" "HTTPS reachability: $host" "FAIL" "TCP/443 connect failed (no curl/wget available)"
        fi
    fi
done

# ---- 5. Docker daemon (if present) --------------------------------------
echo -e "\n[5/5] Docker daemon check (if applicable)..."

if have_cmd docker; then
    if docker info >/dev/null 2>&1; then
        add_result "Docker" "Docker daemon responsive" "PASS" "docker info succeeded"
    else
        add_result "Docker" "Docker daemon responsive" "FAIL" "docker info failed — check daemon status / user permissions (docker group membership)"
    fi
else
    add_result "Docker" "Docker Installed" "INFO" "Docker not found on PATH — skipping daemon check"
fi

# ---- Baseline diff (Toolchain only) -------------------------------------
if [[ "$PHASE" == "Migrated" && -n "$BASELINE_JSON" ]]; then
    echo -e "\nDiffing toolchain versions against baseline: $BASELINE_JSON"
    if [[ -f "$BASELINE_JSON" ]]; then
        if have_cmd python3; then
            # Use python3 (near-universal on RHEL) for a proper JSON parse
            python3 - "$BASELINE_JSON" "$TOOLVER_TMP" <<'PYEOF' >> "$RESULTS_TMP"
import json, sys

baseline_path, current_path = sys.argv[1], sys.argv[2]

with open(baseline_path) as f:
    baseline = json.load(f)
base_tools = {t["tool"]: t["version"] for t in baseline.get("ToolVersions", [])}

current = []
with open(current_path) as f:
    for line in f:
        line = line.strip()
        if line:
            current.append(json.loads(line))
curr_tools = {t["tool"]: t["version"] for t in current}

import datetime
all_tools = set(base_tools) | set(curr_tools)
for tool in sorted(all_tools):
    b = base_tools.get(tool)
    c = curr_tools.get(tool)
    ts = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    if not b and not c:
        continue
    elif b == c:
        status, detail = "PASS", c
    elif not b:
        status, detail = "WARN", f"Tool absent in baseline, present now: {c}"
    elif not c:
        status, detail = "FAIL", f"Tool present in baseline ({b}), missing now"
    else:
        status, detail = "WARN", f"Baseline: {b} | Migrated: {c}"
    detail_esc = detail.replace("\\", "\\\\").replace('"', '\\"')
    print(f'{{"Category":"BaselineDiff","Check":"Version match: {tool}","Status":"{status}","Detail":"{detail_esc}","Timestamp":"{ts}"}}')
PYEOF
        else
            add_result "BaselineDiff" "Baseline Diff" "WARN" "python3 not available — skipping automated toolchain diff, compare JSON files manually"
        fi
    else
        add_result "BaselineDiff" "Baseline File" "FAIL" "Baseline JSON not found at $BASELINE_JSON"
    fi
fi

# ---- Assemble JSON report -------------------------------------------------
{
    printf '{\n'
    printf '  "Hostname": "%s",\n' "$(json_escape "$HOSTNAME_VAL")"
    printf '  "Phase": "%s",\n' "$PHASE"
    printf '  "Timestamp": "%s",\n' "$TIMESTAMP"
    printf '  "ToolVersions": [\n'
    paste_lines="$(sed 's/^/    /' "$TOOLVER_TMP" | paste -sd, -)"
    printf '%s\n' "$paste_lines"
    printf '  ],\n'
    printf '  "Results": [\n'
    result_lines="$(sed 's/^/    /' "$RESULTS_TMP" | paste -sd, -)"
    printf '%s\n' "$result_lines"
    printf '  ]\n'
    printf '}\n'
} > "$JSON_PATH"

echo -e "\nJSON report written to: $JSON_PATH"

# ---- Assemble HTML report (dark theme, matches Windows script) ---------
html_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    printf '%s' "$s"
}

PASS_COUNT=0; WARN_COUNT=0; FAIL_COUNT=0; INFO_COUNT=0
ROWS=""
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    category="$(echo "$line" | grep -oP '(?<="Category":")[^"]*' )"
    check="$(echo "$line" | grep -oP '(?<="Check":")[^"]*' )"
    status="$(echo "$line" | grep -oP '(?<="Status":")[^"]*' )"
    detail="$(echo "$line" | grep -oP '(?<="Detail":")[^"]*' )"

    case "$status" in
        PASS) cls="pass"; ((PASS_COUNT++)) ;;
        WARN) cls="warn"; ((WARN_COUNT++)) ;;
        FAIL) cls="fail"; ((FAIL_COUNT++)) ;;
        *)    cls="info"; ((INFO_COUNT++)) ;;
    esac

    detail_html="$(html_escape "$detail")"
    ROWS="${ROWS}<tr class=\"${cls}\"><td>${category}</td><td>${check}</td><td class=\"status\">${status}</td><td>${detail_html}</td></tr>
"
done < "$RESULTS_TMP"

SUMMARY_LINE="PASS: $PASS_COUNT &nbsp;|&nbsp; WARN: $WARN_COUNT &nbsp;|&nbsp; FAIL: $FAIL_COUNT &nbsp;|&nbsp; INFO: $INFO_COUNT"

cat > "$HTML_PATH" <<HTMLEOF
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Build Agent Checks - ${HOSTNAME_VAL} (${PHASE})</title>
<style>
  body { background:#1e1e1e; color:#d4d4d4; font-family:Consolas,'Segoe UI',monospace; margin:2em; }
  h1 { color:#4fc3f7; }
  .meta { color:#9e9e9e; margin-bottom:1em; }
  table { border-collapse:collapse; width:100%; }
  th, td { padding:6px 10px; text-align:left; border-bottom:1px solid #333; font-size:0.9em; }
  th { background:#252526; color:#4fc3f7; position:sticky; top:0; }
  tr.pass .status { color:#4caf50; font-weight:bold; }
  tr.warn .status { color:#ffb74d; font-weight:bold; }
  tr.fail .status { color:#e57373; font-weight:bold; }
  tr.info .status { color:#90a4ae; font-weight:bold; }
  tr.fail { background:#2a1a1a; }
  tr.warn { background:#2a2410; }
  .summary { margin-bottom:1em; font-size:1.05em; }
</style>
</head>
<body>
  <h1>Build Agent Checks: ${HOSTNAME_VAL}</h1>
  <div class="meta">Phase: ${PHASE} &nbsp;|&nbsp; Generated: ${TIMESTAMP}</div>
  <div class="summary">${SUMMARY_LINE}</div>
  <table>
    <tr><th>Category</th><th>Check</th><th>Status</th><th>Detail</th></tr>
    ${ROWS}
  </table>
</body>
</html>
HTMLEOF

echo "HTML report written to: $HTML_PATH"

# ---- Console summary ------------------------------------------------------
echo -e "\n=== Summary: $PASS_COUNT PASS / $WARN_COUNT WARN / $FAIL_COUNT FAIL ==="
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo -e "\nFAILed checks:"
    grep '"Status":"FAIL"' "$RESULTS_TMP" | while IFS= read -r line; do
        category="$(echo "$line" | grep -oP '(?<="Category":")[^"]*')"
        check="$(echo "$line" | grep -oP '(?<="Check":")[^"]*')"
        detail="$(echo "$line" | grep -oP '(?<="Detail":")[^"]*')"
        echo "  - [$category] $check: $detail"
    done
fi
