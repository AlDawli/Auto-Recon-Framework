#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Auto Recon Framework — Setup Script
# Installs: nmap, subfinder, httpx, nuclei, gowitness, Python deps
# Supports: Ubuntu/Debian, macOS (Homebrew), Kali Linux
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${BLUE}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[✓]${RESET}    $*"; }
warning() { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[✗]${RESET}    $*"; exit 1; }
step()    { echo -e "\n${CYAN}${BOLD}══ $* ══${RESET}"; }

# ── Header ───────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
echo -e "${RESET}"
echo -e "  ${BOLD}Auto Recon Framework Setup v1.0.0${RESET}"
echo -e "  Installing: nmap · subfinder · httpx · nuclei · gowitness"
echo ""

# ── Detect OS ─────────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
GOARCH="amd64"
[[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]] && GOARCH="arm64"

info "Detected OS: $OS ($ARCH)"

# ── Check Python ──────────────────────────────────────────────────────────────
step "Python Environment"
if ! command -v python3 &>/dev/null; then
    error "Python 3.10+ is required. Please install it first."
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
info "Python version: $PYTHON_VERSION"

if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"; then
    success "Python version OK"
else
    error "Python 3.10+ required, found $PYTHON_VERSION"
fi

# ── Python dependencies ───────────────────────────────────────────────────────
step "Python Dependencies"
if [[ -f "requirements.txt" ]]; then
    if command -v pip3 &>/dev/null; then
        pip3 install -q -r requirements.txt
        success "Python packages installed"
    else
        error "pip3 not found. Install it with: sudo apt install python3-pip"
    fi
else
    warning "requirements.txt not found — skipping Python packages"
fi

# ── System tool installer ─────────────────────────────────────────────────────
install_apt() {
    info "Installing $1 via apt..."
    sudo apt-get install -y -q "$1" 2>/dev/null && success "$1 installed" || warning "Failed to install $1"
}

install_brew() {
    info "Installing $1 via Homebrew..."
    brew install "$1" 2>/dev/null && success "$1 installed" || warning "Failed to install $1"
}

# ── nmap ─────────────────────────────────────────────────────────────────────
step "nmap"
if command -v nmap &>/dev/null; then
    success "nmap already installed: $(nmap --version | head -1)"
else
    case "$OS" in
        Linux)  install_apt nmap ;;
        Darwin) install_brew nmap ;;
        *)      warning "Unknown OS — install nmap manually" ;;
    esac
fi

# ── Go tools installer ────────────────────────────────────────────────────────
install_go_tool() {
    local name="$1"
    local pkg="$2"
    local bin="$3"

    if command -v "$bin" &>/dev/null; then
        success "$name already installed"
        return
    fi

    if ! command -v go &>/dev/null; then
        warning "Go not found — installing $name via binary release"
        install_go_binary "$name" "$pkg" "$bin"
        return
    fi

    info "Installing $name via go install..."
    go install -v "$pkg@latest" 2>/dev/null && success "$name installed" || warning "Failed to install $name"
}

install_go_binary() {
    local name="$1"
    local github_repo="$2"
    local bin="$3"
    local install_dir="${HOME}/.local/bin"
    mkdir -p "$install_dir"

    # This is a simplified downloader — real implementation would pull GitHub releases
    warning "$name requires Go. Install Go from https://go.dev/dl/ then run:"
    warning "  go install $github_repo@latest"
}

# Add Go bin to PATH if Go is installed
if command -v go &>/dev/null; then
    export PATH="$PATH:$(go env GOPATH)/bin"
    echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc 2>/dev/null || true
    echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc 2>/dev/null || true
fi

# ── subfinder ─────────────────────────────────────────────────────────────────
step "subfinder"
install_go_tool "subfinder" \
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" \
    "subfinder"

# ── httpx ─────────────────────────────────────────────────────────────────────
step "httpx"
install_go_tool "httpx" \
    "github.com/projectdiscovery/httpx/cmd/httpx" \
    "httpx"

# ── nuclei ────────────────────────────────────────────────────────────────────
step "nuclei"
install_go_tool "nuclei" \
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei" \
    "nuclei"

if command -v nuclei &>/dev/null; then
    info "Updating nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null && success "Templates updated" || warning "Template update failed"
fi

# ── gowitness (screenshots) ───────────────────────────────────────────────────
step "gowitness (screenshots)"
install_go_tool "gowitness" \
    "github.com/sensepost/gowitness" \
    "gowitness"

# ── Chromium fallback ─────────────────────────────────────────────────────────
if ! command -v gowitness &>/dev/null; then
    info "Checking for Chromium as screenshot fallback..."
    if command -v chromium &>/dev/null || command -v chromium-browser &>/dev/null; then
        success "Chromium available as screenshot fallback"
    else
        case "$OS" in
            Linux)  install_apt chromium ;;
            Darwin) install_brew --cask chromium ;;
        esac
    fi
fi

# ── Output directories ────────────────────────────────────────────────────────
step "Output Directories"
mkdir -p output/{reports,screenshots,json}
success "Created output/ directories"

# ── Default config ────────────────────────────────────────────────────────────
step "Configuration"
if [[ ! -f "config.yaml" ]]; then
    python3 main.py --init-config && success "Generated config.yaml"
else
    info "config.yaml already exists — skipping"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  Setup Complete!${RESET}"
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  Tool availability:"
for tool in nmap subfinder httpx nuclei gowitness; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${RESET}  $tool"
    else
        echo -e "  ${RED}✗${RESET}  $tool ${YELLOW}(not found)${RESET}"
    fi
done

echo ""
echo -e "  ${BOLD}Quick start:${RESET}"
echo -e "  ${CYAN}python main.py -t example.com${RESET}"
echo ""
echo -e "  ${BOLD}Docker:${RESET}"
echo -e "  ${CYAN}docker-compose -f docker/docker-compose.yml run --rm recon -t example.com${RESET}"
echo ""
