#!/usr/bin/env bash
# ==============================================================================
# goshark Installation Script
# Installs system dependencies, Python environment, builds Go engines,
# and configures live packet capture permissions.
# ==============================================================================

set -euo pipefail

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
RESET="\033[0m"

log_info() {
    echo -e "${BLUE}[INFO]${RESET} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${RESET} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${RESET} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${RESET} $1"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

AUTO_YES=false
INSTALL_SYSTEM_DEPS=true
CONFIGURE_SETCAP=true
CREATE_DESKTOP_ENTRY=true

print_usage() {
    cat <<EOF
Usage: ./install.sh [OPTIONS]

Options:
  -y, --yes              Assume yes to all prompts (non-interactive mode)
  --no-system-deps       Skip installing system packages via apt/dnf/pacman/zypper
  --no-setcap            Skip configuring packet capture capabilities (cap_net_raw)
  --no-desktop           Skip creating a desktop launcher icon
  -h, --help             Show this help message
EOF
}

# Parse command line flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes)
            AUTO_YES=true
            shift
            ;;
        --no-system-deps)
            INSTALL_SYSTEM_DEPS=false
            shift
            ;;
        --no-setcap)
            CONFIGURE_SETCAP=false
            shift
            ;;
        --no-desktop)
            CREATE_DESKTOP_ENTRY=false
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

echo -e "${BOLD}=====================================================${RESET}"
echo -e "${BOLD}         goshark Automated Installer                 ${RESET}"
echo -e "${BOLD}=====================================================${RESET}"
echo ""

# 1. OS check
OS_TYPE="$(uname -s)"
if [[ "$OS_TYPE" != "Linux" ]]; then
    log_warn "Current operating system is '${OS_TYPE}'."
    log_warn "goshark is designed and verified for Linux (uses Linux AF_UNIX and libpcap)."
    log_warn "If you are on Windows, we strongly recommend running inside WSL2 (Ubuntu)."
    if [[ "$AUTO_YES" != true ]]; then
        read -r -p "Do you want to continue anyway? [y/N] " response
        if [[ ! "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            log_info "Installation aborted."
            exit 0
        fi
    fi
fi

# Helper for sudo
SUDO=""
if [[ $EUID -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        log_warn "'sudo' command not found. You may need root privileges for system packages."
    fi
fi

# 2. System dependencies
if [[ "$INSTALL_SYSTEM_DEPS" == true ]]; then
    log_info "Checking and installing native dependencies..."

    if command -v apt-get >/dev/null 2>&1; then
        log_info "Detected Debian/Ubuntu-based distribution (apt-get)."
        DEPS=(
            build-essential
            libpcap-dev
            python3
            python3-pip
            python3-venv
            libxkbcommon0
            xkb-data
            libegl1
            libgl1
            libxcb-cursor0
            libxcb-xinerama0
            libcap2-bin
        )
        if [[ -n "$SUDO" || $EUID -eq 0 ]]; then
            $SUDO apt-get update -y
            $SUDO apt-get install -y "${DEPS[@]}"
            log_success "System dependencies installed via apt."
        else
            log_warn "Cannot run sudo. If dependencies are missing, install: ${DEPS[*]}"
        fi

    elif command -v dnf >/dev/null 2>&1; then
        log_info "Detected Fedora/RHEL-based distribution (dnf)."
        DEPS=(
            gcc
            libpcap-devel
            python3
            python3-pip
            python3-devel
            libxkbcommon
            xkbcomp
            mesa-libEGL
            mesa-libGL
            libcap
        )
        if [[ -n "$SUDO" || $EUID -eq 0 ]]; then
            $SUDO dnf install -y "${DEPS[@]}"
            log_success "System dependencies installed via dnf."
        else
            log_warn "Cannot run sudo. If dependencies are missing, install: ${DEPS[*]}"
        fi

    elif command -v pacman >/dev/null 2>&1; then
        log_info "Detected Arch Linux distribution (pacman)."
        DEPS=(
            base-devel
            libpcap
            python
            python-pip
            libxkbcommon
            xkeyboard-config
            libglvnd
            libcap
        )
        if [[ -n "$SUDO" || $EUID -eq 0 ]]; then
            $SUDO pacman -S --needed --noconfirm "${DEPS[@]}"
            log_success "System dependencies installed via pacman."
        else
            log_warn "Cannot run sudo. If dependencies are missing, install: ${DEPS[*]}"
        fi

    elif command -v zypper >/dev/null 2>&1; then
        log_info "Detected openSUSE distribution (zypper)."
        DEPS=(
            patterns-devel-base-devel_basis
            libpcap-devel
            python3
            python3-pip
            libxkbcommon0
            Mesa-libEGL1
            Mesa-libGL1
            libcap-progs
        )
        if [[ -n "$SUDO" || $EUID -eq 0 ]]; then
            $SUDO zypper install -y "${DEPS[@]}"
            log_success "System dependencies installed via zypper."
        else
            log_warn "Cannot run sudo. If dependencies are missing, install: ${DEPS[*]}"
        fi
    else
        log_warn "No recognized package manager (apt-get, dnf, pacman, zypper). Please ensure libpcap, gcc, Python 3.10+, and Qt libraries are installed."
    fi
else
    log_info "Skipping system packages (--no-system-deps specified)."
fi

# 3. Check Go installation
log_info "Verifying Go compiler..."
if ! command -v go >/dev/null 2>&1; then
    log_error "Go compiler ('go') was not found in PATH."
    echo ""
    echo "goshark requires Go to compile the backend capture engine."
    echo "Please install Go from your package manager (e.g. 'sudo apt install golang-go')"
    echo "or download the official binary from: https://go.dev/dl/"
    exit 1
fi
GO_VERSION="$(go version)"
log_success "Found Go: $GO_VERSION"

# 4. Check Python installation
log_info "Verifying Python 3..."
PYTHON_BIN=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        # Check python version >= 3.10
        if "$candidate" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) and sys.version_info < (3, 16) else 1)" 2>/dev/null; then
            PYTHON_BIN="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    log_error "Python 3 (version 3.10 through 3.15) was not found."
    echo "Please install a compatible Python version before continuing."
    exit 1
fi
log_success "Found Python: $("$PYTHON_BIN" --version)"

# 5. Set up Python virtual environment
VENV_DIR="$SCRIPT_DIR/.venv"
log_info "Setting up Python virtual environment in '$VENV_DIR'..."
if [[ ! -d "$VENV_DIR" ]]; then
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

log_info "Upgrading pip and installing PySide6 / goshark..."
"$VENV_PIP" install --upgrade pip
"$VENV_PIP" install -e "$SCRIPT_DIR"
log_success "Python package 'goshark' installed successfully in virtual environment."

# 6. Compile Go binaries
log_info "Compiling Go engine and CLI utilities..."
mkdir -p "$SCRIPT_DIR/bin"

log_info "Building bin/gosharkd..."
go build -o "$SCRIPT_DIR/bin/gosharkd" "$SCRIPT_DIR/cmd/gosharkd"

log_info "Building bin/tgoshark..."
go build -o "$SCRIPT_DIR/bin/tgoshark" "$SCRIPT_DIR/cmd/tgoshark"

log_info "Building bin/goedit..."
go build -o "$SCRIPT_DIR/bin/goedit" "$SCRIPT_DIR/cmd/goedit"

# Also place gosharkd into .venv/bin so goshark can always find it next to sys.executable
cp "$SCRIPT_DIR/bin/gosharkd" "$VENV_DIR/bin/gosharkd"

log_success "Compiled Go binaries: bin/gosharkd, bin/tgoshark, bin/goedit."

# 7. Configure capture permissions (setcap)
if [[ "$CONFIGURE_SETCAP" == true ]]; then
    if command -v setcap >/dev/null 2>&1 && [[ -n "$SUDO" || $EUID -eq 0 ]]; then
        log_info "Granting raw network capture permissions to gosharkd and tgoshark..."
        set +e
        $SUDO setcap cap_net_raw,cap_net_admin=eip "$SCRIPT_DIR/bin/gosharkd"
        $SUDO setcap cap_net_raw,cap_net_admin=eip "$VENV_DIR/bin/gosharkd"
        $SUDO setcap cap_net_raw,cap_net_admin=eip "$SCRIPT_DIR/bin/tgoshark"
        set -e
        log_success "Network capture permissions configured (cap_net_raw,cap_net_admin)."
    else
        log_warn "setcap not configured. To enable live capture without running as root, run:"
        echo "  sudo setcap cap_net_raw,cap_net_admin=eip $SCRIPT_DIR/bin/gosharkd"
        echo "  sudo setcap cap_net_raw,cap_net_admin=eip $SCRIPT_DIR/bin/tgoshark"
    fi
fi

# 8. Create runner script
RUNNER="$SCRIPT_DIR/run.sh"
cat << 'RUNNER_EOF' > "$RUNNER"
#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$DIR/.venv/bin/goshark" ]; then
    exec "$DIR/.venv/bin/goshark" "$@"
elif command -v goshark >/dev/null 2>&1; then
    exec goshark "$@"
else
    echo "Error: goshark executable not found. Please run ./install.sh first." >&2
    exit 1
fi
RUNNER_EOF
chmod +x "$RUNNER"

# 9. Optional Desktop Launcher
if [[ "$CREATE_DESKTOP_ENTRY" == true && -d "$HOME/.local/share/applications" ]]; then
    DESKTOP_FILE="$HOME/.local/share/applications/goshark.desktop"
    ICON_FILE="$SCRIPT_DIR/goshark/assets/goshark-logo.png"
    cat << DESKTOP_EOF > "$DESKTOP_FILE"
[Desktop Entry]
Version=1.0
Type=Application
Name=Goshark
GenericName=Packet Analyzer
Comment=Native Qt Widgets packet analyzer with Go capture engine
Exec=$RUNNER %f
Icon=$ICON_FILE
Terminal=false
Categories=Network;Security;Development;
MimeType=application/vnd.tcpdump.pcap;application/x-pcapng;
DESKTOP_EOF
    chmod +x "$DESKTOP_FILE"
    log_success "Desktop shortcut created: $DESKTOP_FILE"
fi

echo ""
echo -e "${GREEN}${BOLD}=====================================================${RESET}"
echo -e "${GREEN}${BOLD}         Installation Completed Successfully!        ${RESET}"
echo -e "${GREEN}${BOLD}=====================================================${RESET}"
echo ""
echo -e "${BOLD}How to launch goshark:${RESET}"
echo "  1. Quick run:          ./run.sh"
echo "  2. Open a capture:     ./run.sh testdata/http.pcap"
echo "  3. From active venv:   source .venv/bin/activate && goshark"
echo ""
echo -e "${BOLD}Command-line utilities:${RESET}"
echo "  • List interfaces:     ./bin/tgoshark --interfaces"
echo "  • Live capture CLI:    ./bin/tgoshark --interface <name> --display-filter 'tcp.port == 80'"
echo "  • Offline CLI view:    ./bin/tgoshark --read testdata/http.pcap"
echo "  • PCAP edit/slice:     ./bin/goedit -help"
echo ""
echo -e "${BOLD}Run test suites:${RESET}"
echo "  go test ./..."
echo "  QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest discover -s tests -v"
echo ""
