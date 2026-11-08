#!/usr/bin/env bash
# =============================================================================
# CyberGuard AI — Linux Collector Installer
# =============================================================================
#
# Installs, uninstalls, and manages the CyberGuard Linux Collector as a
# systemd service.
#
# What "install" does (in order):
#
#   1. Verify root (euid == 0)
#   2. Detect the package manager (apt / dnf / yum / pacman / apk / zypper)
#   3. Install runtime deps: python3, python3-venv, python3-pip, and
#      python3-cryptography (for Fernet) — package name varies per distro
#   4. Create the "cyberguard" system user + group (no shell, no home)
#   5. Create the FHS directories:
#        /etc/cyberguard/collector       (0750 root:cyberguard)
#        /var/lib/cyberguard/collector   (0750 root:cyberguard)
#        /var/log/cyberguard             (0755 root:cyberguard)
#        /opt/cyberguard                 (0755 root:cyberguard)
#   6. Create an isolated Python venv at /opt/cyberguard/venv
#   7. pip install the collector's requirements into that venv
#   8. Copy the collector scripts into /opt/cyberguard/collector/
#   9. Render and install the systemd unit (via service.py write)
#  10. systemctl daemon-reload && enable && start
#  11. (Optional) Enroll the collector with --enroll <token>
#
# Why a venv at /opt/cyberguard/venv
# ----------------------------------
# System pythons on most distros are "externally managed" (PEP 668).
# pip install into the system python fails or requires --break-system-
# packages (a footgun). A dedicated venv at a fixed path is:
#   - Isolated from system package upgrades
#   - Explicit in the unit's ExecStart= (no PATH mystery)
#   - Recoverable (delete + recreate on broken state)
#   - Portable (same layout on every distro)
#
# Why a dedicated user (cyberguard)
# ---------------------------------
# The service unit currently runs as root (needed to read Security-
# relevant logs). The user/group exists for:
#   - File ownership: config/state files are root:cyberguard 0750/0640
#   - Future-proofing: a Phase 13 non-root mode can chgrp to cyberguard
#   - Auditing: log entries say "group=cyberguard", not just "root"
#
# Usage
# -----
#   sudo ./install_service.sh install
#   sudo ./install_service.sh install --enroll cgc_abc123...
#   sudo ./install_service.sh uninstall
#   sudo ./install_service.sh start
#   sudo ./install_service.sh stop
#   sudo ./install_service.sh restart
#   sudo ./install_service.sh status
#   sudo ./install_service.sh logs          # tail journald for the unit
#   sudo ./install_service.sh enroll cgc_abc123...
#
# Exit codes
# ----------
#   0   Success
#   1   General error (dependency install failed, file missing, etc.)
#   2   Not running as root
#   3   Unsupported package manager / OS
# =============================================================================

set -euo pipefail


# ============================================================================
# CONSTANTS
# ============================================================================

SERVICE_NAME="cyberguard-collector"
SERVICE_USER="cyberguard"
SERVICE_GROUP="cyberguard"

CONFIG_DIR="/etc/cyberguard/collector"
STATE_DIR="/var/lib/cyberguard/collector"
LOG_DIR="/var/log/cyberguard"
INSTALL_DIR="/opt/cyberguard"
VENV_DIR="${INSTALL_DIR}/venv"
APP_DIR="${INSTALL_DIR}/collector"
MAIN_SCRIPT="${APP_DIR}/main.py"
SERVICE_SCRIPT="${APP_DIR}/service.py"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"


# ============================================================================
# COLORS + OUTPUT HELPERS
# ============================================================================

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'
    C_GRAY=$'\033[90m'
else
    C_RESET="" C_BOLD="" C_RED="" C_GREEN="" C_YELLOW="" C_CYAN="" C_GRAY=""
fi

banner() {
    echo
    echo "${C_CYAN}${C_BOLD}══════════════════════════════════════════════════════════════${C_RESET}"
    echo "${C_CYAN}${C_BOLD}  $*${C_RESET}"
    echo "${C_CYAN}${C_BOLD}══════════════════════════════════════════════════════════════${C_RESET}"
    echo
}

step()  { echo "  ${C_BOLD}→${C_RESET} $*"; }
ok()    { echo "  ${C_GREEN}✓${C_RESET} $*"; }
warn()  { echo "  ${C_YELLOW}⚠${C_RESET} $*"; }
fail()  { echo "  ${C_RED}✗${C_RESET} $*" >&2; }
die()   { fail "$*"; exit 1; }


# ============================================================================
# PREFLIGHT
# ============================================================================

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo
        fail "This script must be run as root."
        echo
        echo "  Try:"
        echo "    sudo ./install_service.sh $*"
        echo
        exit 2
    fi
}

require_systemd() {
    if ! command -v systemctl >/dev/null 2>&1; then
        die "systemctl not found — this system does not run systemd. \
The CyberGuard Linux collector requires systemd for service management. \
For non-systemd systems, run 'python3 main.py run' under your init \
system's supervisor."
    fi
}

require_main_script() {
    if [[ ! -f "${SCRIPT_DIR}/main.py" ]]; then
        die "main.py not found at ${SCRIPT_DIR}/main.py. \
install_service.sh must live in the same directory as main.py."
    fi
    if [[ ! -f "${SCRIPT_DIR}/service.py" ]]; then
        die "service.py not found at ${SCRIPT_DIR}/service.py."
    fi
}


# ============================================================================
# PACKAGE MANAGER DETECTION + DEPENDENCY INSTALL
# ============================================================================

detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    elif command -v apk >/dev/null 2>&1; then
        echo "apk"
    elif command -v zypper >/dev/null 2>&1; then
        echo "zypper"
    else
        echo "unknown"
    fi
}

install_system_deps() {
    local pm
    pm="$(detect_pkg_manager)"
    step "Detected package manager: ${pm}"

    case "${pm}" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            step "apt-get update"
            apt-get update -qq
            step "Installing python3, python3-venv, python3-pip"
            apt-get install -y -qq python3 python3-venv python3-pip \
                ca-certificates curl >/dev/null
            # cryptography — prefer the distro package (faster than building)
            apt-get install -y -qq python3-cryptography >/dev/null 2>&1 || \
                warn "python3-cryptography not available via apt — venv pip will install it"
            ;;
        dnf)
            step "Installing python3, python3-pip, python3-cryptography"
            dnf install -y -q python3 python3-pip python3-cryptography \
                ca-certificates curl >/dev/null
            ;;
        yum)
            step "Installing python3, python3-pip (yum)"
            yum install -y -q python3 python3-pip ca-certificates curl >/dev/null
            ;;
        pacman)
            step "pacman -Sy python, pip, python-cryptography"
            pacman -Sy --noconfirm python python-pip python-cryptography \
                ca-certificates curl >/dev/null
            ;;
        apk)
            step "apk add python3 py3-pip py3-cryptography"
            apk add --quiet python3 py3-pip py3-cryptography \
                ca-certificates curl >/dev/null
            ;;
        zypper)
            step "zypper install python3, python3-pip, python3-cryptography"
            zypper --quiet --non-interactive install -y \
                python3 python3-pip python3-cryptography \
                ca-certificates curl >/dev/null
            ;;
        unknown)
            fail "No supported package manager found (apt/dnf/yum/pacman/apk/zypper)."
            fail "Install Python 3.10+, pip, and cryptography manually, then re-run."
            exit 3
            ;;
    esac

    ok "System dependencies installed"
}


# ============================================================================
# USER + GROUP
# ============================================================================

create_service_user() {
    step "Checking ${SERVICE_USER} user/group"

    if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
        groupadd --system "${SERVICE_GROUP}"
        ok "Created group ${SERVICE_GROUP}"
    else
        ok "Group ${SERVICE_GROUP} already exists"
    fi

    if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
        useradd \
            --system \
            --gid "${SERVICE_GROUP}" \
            --no-create-home \
            --home-dir "/nonexistent" \
            --shell "/usr/sbin/nologin" \
            --comment "CyberGuard Collector" \
            "${SERVICE_USER}"
        ok "Created user ${SERVICE_USER}"
    else
        ok "User ${SERVICE_USER} already exists"
    fi
}


# ============================================================================
# DIRECTORIES + PERMISSIONS
# ============================================================================

create_directories() {
    step "Creating FHS directories"

    for dir in "${CONFIG_DIR}" "${STATE_DIR}"; do
        mkdir -p "${dir}"
        chmod 0750 "${dir}"
        chown "root:${SERVICE_GROUP}" "${dir}"
    done

    mkdir -p "${LOG_DIR}"
    chmod 0755 "${LOG_DIR}"
    chown "root:${SERVICE_GROUP}" "${LOG_DIR}"

    mkdir -p "${INSTALL_DIR}" "${APP_DIR}"
    chmod 0755 "${INSTALL_DIR}" "${APP_DIR}"
    chown "root:${SERVICE_GROUP}" "${INSTALL_DIR}" "${APP_DIR}"

    ok "Directory structure ready"
    echo "${C_GRAY}      ${CONFIG_DIR}${C_RESET}"
    echo "${C_GRAY}      ${STATE_DIR}${C_RESET}"
    echo "${C_GRAY}      ${LOG_DIR}${C_RESET}"
    echo "${C_GRAY}      ${APP_DIR}${C_RESET}"
}


# ============================================================================
# PYTHON VENV + DEPS
# ============================================================================

create_venv() {
    step "Creating virtualenv at ${VENV_DIR}"

    if [[ -d "${VENV_DIR}" ]]; then
        warn "Existing venv at ${VENV_DIR} — preserving it (delete manually to rebuild)"
    else
        python3 -m venv "${VENV_DIR}"
        ok "Created venv"
    fi

    local py="${VENV_DIR}/bin/python3"
    if [[ ! -x "${py}" ]]; then
        die "venv python3 not found at ${py} — venv creation failed"
    fi

    step "Upgrading pip inside the venv"
    "${py}" -m pip install --quiet --upgrade pip

    step "Installing collector requirements"
    local req_file="${SCRIPT_DIR}/requirements.txt"
    if [[ -f "${req_file}" ]]; then
        "${py}" -m pip install --quiet -r "${req_file}"
        ok "Requirements installed from ${req_file}"
    else
        # No requirements.txt shipped — install the minimum set inline
        warn "requirements.txt not found — installing minimum dependencies"
        "${py}" -m pip install --quiet \
            "httpx>=0.27" \
            "cryptography>=42"
        ok "Minimum dependencies installed (httpx, cryptography)"
    fi

    # Verify cryptography is importable (most common install-time failure)
    if ! "${py}" -c "from cryptography.fernet import Fernet" 2>/dev/null; then
        die "cryptography is not importable in the venv — install failed. \
Try: ${py} -m pip install cryptography"
    fi
    ok "cryptography importable in venv"
}


# ============================================================================
# APP FILES
# ============================================================================

copy_app_files() {
    step "Copying collector scripts to ${APP_DIR}"

    # Copy every .py file plus the requirements.txt if present
    for f in "${SCRIPT_DIR}"/*.py; do
        [[ -e "${f}" ]] || continue
        cp -f "${f}" "${APP_DIR}/"
    done

    [[ -f "${SCRIPT_DIR}/requirements.txt" ]] && \
        cp -f "${SCRIPT_DIR}/requirements.txt" "${APP_DIR}/"

    chown -R "root:${SERVICE_GROUP}" "${APP_DIR}"
    chmod 0755 "${APP_DIR}"
    find "${APP_DIR}" -maxdepth 1 -type f -name "*.py" -exec chmod 0755 {} \;
    find "${APP_DIR}" -maxdepth 1 -type f -name "*.txt" -exec chmod 0644 {} \;

    ok "Scripts copied ($(find "${APP_DIR}" -maxdepth 1 -name '*.py' | wc -l) Python files)"
}


# ============================================================================
# SYSTEMD UNIT
# ============================================================================

write_systemd_unit() {
    step "Rendering and writing systemd unit"

    local py="${VENV_DIR}/bin/python3"
    if [[ ! -x "${py}" ]]; then
        die "venv python not found — cannot render correct ExecStart="
    fi

    # service.py write requires root; we already checked. But service.py
    # in SCRIPT_DIR resolves paths relative to itself, which points at
    # the SOURCE dir — not the installed copy. Pass --path and override
    # the render via environment. Simplest: use the venv python + call
    # the INSTALLED service.py which knows the correct main.py path.
    local svc_py="${APP_DIR}/service.py"
    if [[ ! -f "${svc_py}" ]]; then
        die "service.py not found at ${svc_py}"
    fi

    # Render the unit using the installed service.py. It auto-detects
    # paths from its own location and sys.executable.
    "${py}" "${svc_py}" write
    ok "systemd unit installed"
}


# ============================================================================
# SYSTEMCTL
# ============================================================================

systemctl_reload_enable_start() {
    step "systemctl daemon-reload"
    systemctl daemon-reload

    step "systemctl enable ${SERVICE_NAME}"
    systemctl enable "${SERVICE_NAME}" >/dev/null

    step "systemctl start ${SERVICE_NAME}"
    systemctl start "${SERVICE_NAME}"

    # Give systemd 2s to settle before checking status
    sleep 2

    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        ok "Service is running"
    else
        fail "Service failed to start. Recent logs:"
        journalctl -u "${SERVICE_NAME}" --no-pager -n 30 || true
        exit 1
    fi
}


# ============================================================================
# ENROLLMENT
# ============================================================================

enroll_collector() {
    local token="$1"
    if [[ -z "${token}" ]]; then
        die "Empty enrollment token provided"
    fi

    step "Enrolling collector with provided token"
    local py="${VENV_DIR}/bin/python3"
    "${py}" "${APP_DIR}/main.py" enroll "${token}"

    if [[ $? -ne 0 ]]; then
        fail "Enrollment failed — the service is installed but not enrolled."
        fail "Re-run enrollment with: ${py} ${APP_DIR}/main.py enroll <token>"
        return 1
    fi

    # Restart so the reader picks up the freshly-stored credential
    step "Restarting service to pick up the credential"
    systemctl restart "${SERVICE_NAME}"
    sleep 2

    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        ok "Service restarted and enrolled"
    else
        fail "Service failed to restart after enrollment"
        journalctl -u "${SERVICE_NAME}" --no-pager -n 30 || true
        return 1
    fi
}


# ============================================================================
# COMMANDS
# ============================================================================

cmd_install() {
    local enroll_token=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --enroll)
                shift
                enroll_token="${1:-}"
                [[ -z "${enroll_token}" ]] && die "--enroll requires a token argument"
                shift
                ;;
            *)
                die "Unknown argument for install: $1"
                ;;
        esac
    done

    banner "Installing CyberGuard AI Linux Collector"
    require_root "$@"
    require_systemd
    require_main_script

    install_system_deps
    create_service_user
    create_directories
    create_venv
    copy_app_files
    write_systemd_unit

    # Enroll BEFORE starting so the first run has a credential and
    # doesn't exit immediately with EXIT_NOT_ENROLLED
    if [[ -n "${enroll_token}" ]]; then
        step "Enrolling before service start"
        local py="${VENV_DIR}/bin/python3"
        if ! "${py}" "${APP_DIR}/main.py" enroll "${enroll_token}"; then
            fail "Enrollment failed."
            fail "The service will be installed but disabled until you enroll."
            fail "Run: sudo ${py} ${APP_DIR}/main.py enroll <new-token>"
            # Still write/enable the unit so the operator can finish manually
            systemctl daemon-reload || true
            systemctl enable "${SERVICE_NAME}" >/dev/null || true
            exit 1
        fi
        ok "Enrolled successfully"
    else
        warn "No enrollment token provided."
        echo
        echo "  Enroll before starting the service:"
        echo "    sudo ${VENV_DIR}/bin/python3 ${APP_DIR}/main.py enroll <token>"
        echo
        echo "  Or install with an inline enroll:"
        echo "    sudo ./install_service.sh install --enroll <token>"
        echo
    fi

    systemctl_reload_enable_start

    # ── Final status panel
    echo
    echo "${C_GREEN}${C_BOLD}  ┌────────────────────────────────────────────────────────┐${C_RESET}"
    echo "${C_GREEN}${C_BOLD}  │  Installation complete — service is RUNNING           │${C_RESET}"
    echo "${C_GREEN}${C_BOLD}  └────────────────────────────────────────────────────────┘${C_RESET}"
    echo
    echo "  Service name:   ${SERVICE_NAME}"
    echo "  Status:         $(systemctl is-active "${SERVICE_NAME}")"
    echo "  Enabled:        $(systemctl is-enabled "${SERVICE_NAME}")"
    echo "  Install dir:    ${INSTALL_DIR}"
    echo "  Config file:    ${CONFIG_DIR}/config.json"
    echo "  State dir:      ${STATE_DIR}"
    echo "  Logs:           journalctl -u ${SERVICE_NAME} -f"
    echo
    echo "  Manage with:"
    echo "    sudo ./install_service.sh status"
    echo "    sudo ./install_service.sh stop"
    echo "    sudo ./install_service.sh restart"
    echo "    sudo ./install_service.sh logs"
    echo "    sudo ./install_service.sh uninstall"
    echo
}

cmd_uninstall() {
    banner "Uninstalling CyberGuard AI Linux Collector"
    require_root "$@"
    require_systemd

    if systemctl list-unit-files "${SERVICE_NAME}.service" >/dev/null 2>&1; then
        step "Stopping service"
        systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
        step "Disabling service"
        systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    fi

    step "Removing systemd unit"
    "${VENV_DIR}/bin/python3" "${APP_DIR}/service.py" uninstall 2>/dev/null || \
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"

    step "systemctl daemon-reload"
    systemctl daemon-reload

    step "Removing app install directory ${INSTALL_DIR}"
    rm -rf "${INSTALL_DIR}"

    ok "Service removed"
    echo
    warn "Config and state data preserved at:"
    echo "${C_GRAY}      ${CONFIG_DIR}${C_RESET}"
    echo "${C_GRAY}      ${STATE_DIR}${C_RESET}"
    echo "${C_GRAY}      ${LOG_DIR}${C_RESET}"
    echo
    echo "  To remove all data:"
    echo "    sudo rm -rf ${CONFIG_DIR} ${STATE_DIR} ${LOG_DIR}"
    echo "    sudo userdel ${SERVICE_USER} 2>/dev/null || true"
    echo "    sudo groupdel ${SERVICE_GROUP} 2>/dev/null || true"
    echo
}

cmd_start() {
    require_root "$@"
    systemctl start "${SERVICE_NAME}"
    sleep 1
    systemctl --no-pager status "${SERVICE_NAME}" || true
}

cmd_stop() {
    require_root "$@"
    systemctl stop "${SERVICE_NAME}"
    sleep 1
    systemctl --no-pager status "${SERVICE_NAME}" || true
}

cmd_restart() {
    require_root "$@"
    systemctl restart "${SERVICE_NAME}"
    sleep 2
    systemctl --no-pager status "${SERVICE_NAME}" || true
}

cmd_status() {
    banner "CyberGuard AI Linux Collector — Status"

    if ! systemctl list-unit-files "${SERVICE_NAME}.service" >/dev/null 2>&1; then
        warn "Service is NOT installed."
        echo "  Install with: sudo ./install_service.sh install"
        return 1
    fi

    echo "  Unit:      ${SERVICE_NAME}"
    echo "  Active:    $(systemctl is-active "${SERVICE_NAME}" 2>/dev/null || echo 'unknown')"
    echo "  Enabled:   $(systemctl is-enabled "${SERVICE_NAME}" 2>/dev/null || echo 'unknown')"
    echo

    # Show collector-level status via main.py (queue, cursor, backend)
    if [[ -x "${VENV_DIR}/bin/python3" ]] && [[ -f "${APP_DIR}/main.py" ]]; then
        "${VENV_DIR}/bin/python3" "${APP_DIR}/main.py" status || true
    else
        warn "Cannot run 'main.py status' — venv or scripts missing"
    fi
    echo

    # Recent journald output
    echo "  Last 10 log lines:"
    journalctl -u "${SERVICE_NAME}" --no-pager -n 10 2>/dev/null | \
        sed 's/^/    /' || true
    echo
}

cmd_logs() {
    journalctl -u "${SERVICE_NAME}" -f
}

cmd_enroll() {
    require_root "$@"
    local token="${1:-}"
    if [[ -z "${token}" ]]; then
        read -rp "Paste enrollment token (cgc_...): " token
    fi
    if [[ -z "${token}" ]]; then
        die "No token provided"
    fi

    if [[ ! -x "${VENV_DIR}/bin/python3" ]]; then
        die "Collector not installed. Run: sudo ./install_service.sh install"
    fi

    enroll_collector "${token}"
}


# ============================================================================
# USAGE + DISPATCH
# ============================================================================

usage() {
    cat <<EOF
CyberGuard AI Linux Collector Installer

Usage: sudo ./install_service.sh <command> [args]

Commands:
  install [--enroll <token>]   Install the collector as a systemd service
  uninstall                    Stop, disable, and remove the service
  start                        Start the installed service
  stop                         Stop the running service
  restart                      Restart the service
  status                       Show service + collector status
  logs                         Tail journald output for the service
  enroll [<token>]             Enroll the installed collector

Examples:
  sudo ./install_service.sh install
  sudo ./install_service.sh install --enroll cgc_abc123def456...
  sudo ./install_service.sh status
  sudo ./install_service.sh logs

Requirements:
  - Linux with systemd
  - Root (via sudo)
  - Network access to your package manager (install)
  - Network access to the CyberGuard backend (runtime)
EOF
}

main() {
    if [[ $# -lt 1 ]]; then
        usage
        exit 1
    fi

    local cmd="$1"
    shift || true

    case "${cmd}" in
        install)    cmd_install "$@" ;;
        uninstall)  cmd_uninstall "$@" ;;
        start)      cmd_start "$@" ;;
        stop)       cmd_stop "$@" ;;
        restart)    cmd_restart "$@" ;;
        status)     cmd_status "$@" ;;
        logs)       cmd_logs "$@" ;;
        enroll)     cmd_enroll "$@" ;;
        -h|--help|help|"")
            usage
            ;;
        *)
            fail "Unknown command: ${cmd}"
            echo
            usage
            exit 1
            ;;
    esac
}

main "$@"