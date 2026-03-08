#!/bin/sh
# Revelion Daemon Installer
# Usage: curl -fsSL https://get.revelion.ai | sh -s -- YOUR_API_TOKEN
#
# Or without token (will need manual auth later):
#   curl -fsSL https://get.revelion.ai | sh

set -e

REPO="RevelionAI/revelion-daemon"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="revelion"
CONFIG_DIR="$HOME/.revelion"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

info() { printf "${CYAN}[revelion]${NC} %s\n" "$1"; }
success() { printf "${GREEN}[revelion]${NC} %s\n" "$1"; }
error() { printf "${RED}[revelion]${NC} %s\n" "$1" >&2; }
dim() { printf "${DIM}%s${NC}\n" "$1"; }

# Parse arguments
API_TOKEN=""
START_DAEMON=true
for arg in "$@"; do
  case "$arg" in
    --no-start) START_DAEMON=false ;;
    --help|-h)
      echo "Usage: install.sh [API_TOKEN] [--no-start]"
      echo ""
      echo "  API_TOKEN    Your Revelion API token (from app.revelion.ai/agents)"
      echo "  --no-start   Install only, don't start the daemon"
      exit 0
      ;;
    *)
      if [ -z "$API_TOKEN" ]; then
        API_TOKEN="$arg"
      fi
      ;;
  esac
done

# Detect OS and architecture
detect_platform() {
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"

  case "$OS" in
    linux)  OS="linux" ;;
    darwin) OS="darwin" ;;
    *)      error "Unsupported OS: $OS"; exit 1 ;;
  esac

  case "$ARCH" in
    x86_64|amd64)   ARCH="amd64" ;;
    aarch64|arm64)   ARCH="arm64" ;;
    *)               error "Unsupported architecture: $ARCH"; exit 1 ;;
  esac

  PLATFORM="${OS}-${ARCH}"
}

# Get latest release tag for daemon
get_latest_version() {
  LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases" \
    | grep -o '"tag_name": *"daemon-v[^"]*"' \
    | head -1 \
    | sed 's/.*"daemon-v\([^"]*\)".*/\1/')

  if [ -z "$LATEST" ]; then
    error "Could not determine latest version. Check your internet connection."
    exit 1
  fi
  VERSION="v${LATEST}"
  TAG="daemon-${VERSION}"
}

# Download binary
download_binary() {
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/revelion-${PLATFORM}"
  TEMP_FILE=$(mktemp)

  info "Downloading revelion ${VERSION} for ${PLATFORM}..."
  dim "  ${DOWNLOAD_URL}"

  if ! curl -fsSL -o "$TEMP_FILE" "$DOWNLOAD_URL"; then
    error "Download failed. Check that release exists for your platform."
    rm -f "$TEMP_FILE"
    exit 1
  fi

  chmod +x "$TEMP_FILE"

  # Install to /usr/local/bin (may need sudo)
  if [ -w "$INSTALL_DIR" ]; then
    mv "$TEMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
  else
    info "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "$TEMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
  fi

  success "Installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"
}

# Configure with API token
configure() {
  if [ -z "$API_TOKEN" ]; then
    return
  fi

  mkdir -p "$CONFIG_DIR"
  cat > "${CONFIG_DIR}/config.json" << EOF
{
  "api_token": "${API_TOKEN}",
  "brain_url": "wss://revelion-brain.fly.dev",
  "sandbox_image": "ghcr.io/revelionai/revelion-sandbox:0.1.0"
}
EOF
  chmod 600 "${CONFIG_DIR}/config.json"
  success "Configured with API token"
}

# Check Docker
check_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo ""
    error "Docker is not installed. The daemon requires Docker to run scan containers."
    info "Install Docker: https://docs.docker.com/get-docker/"
    echo ""
    return 1
  fi

  if ! docker info >/dev/null 2>&1; then
    echo ""
    error "Docker is not running or current user doesn't have permission."
    info "Start Docker or add your user to the docker group:"
    dim "  sudo usermod -aG docker \$USER"
    echo ""
    return 1
  fi

  return 0
}

# Main
main() {
  echo ""
  printf "${BOLD}${CYAN}"
  echo "  ____                 _ _             "
  echo " |  _ \ _____   _____| (_) ___  _ __  "
  echo " | |_) / _ \ \ / / _ \ | |/ _ \| '_ \ "
  echo " |  _ <  __/\ V /  __/ | | (_) | | | |"
  echo " |_| \_\___| \_/ \___|_|_|\___/|_| |_|"
  printf "${NC}"
  echo ""
  info "Daemon Installer"
  echo ""

  detect_platform
  get_latest_version
  download_binary
  configure

  # Check prerequisites
  DOCKER_OK=true
  check_docker || DOCKER_OK=false

  echo ""
  if [ -n "$API_TOKEN" ] && [ "$START_DAEMON" = true ] && [ "$DOCKER_OK" = true ]; then
    success "Starting daemon..."
    echo ""
    exec "${INSTALL_DIR}/${BINARY_NAME}" start
  elif [ -n "$API_TOKEN" ]; then
    success "Installation complete!"
    echo ""
    info "Start the daemon with:"
    dim "  revelion start"
  else
    success "Installation complete!"
    echo ""
    info "Authenticate with your API token (find it at app.revelion.ai/agents):"
    dim "  revelion auth YOUR_API_TOKEN"
    echo ""
    info "Then start the daemon:"
    dim "  revelion start"
  fi
}

main
