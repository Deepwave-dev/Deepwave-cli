#!/bin/bash
# Deepwave CLI Install Script
# Usage: curl -fsSL https://raw.githubusercontent.com/Deepwave-dev/Deepwave-cli/main/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="${HOME}/.local/bin"
BINARY_NAME="deepwave"
REPO_URL="https://github.com/Deepwave-dev/Deepwave-cli"
RELEASE_URL="${REPO_URL}/releases/latest/download"

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"
    
    case "${OS}" in
        linux*)
            PLATFORM="linux"
            ;;
        darwin*)
            PLATFORM="macos"
            ;;
        *)
            echo -e "${RED}❌ Unsupported OS: ${OS}${NC}"
            exit 1
            ;;
    esac
    
    case "${ARCH}" in
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        *)
            echo -e "${RED}❌ Unsupported architecture: ${ARCH}${NC}"
            exit 1
            ;;
    esac
    
    echo -e "${GREEN}✓ Detected platform: ${PLATFORM}-${ARCH}${NC}"
}

# Check if binary exists in PATH
check_existing() {
    if command -v "${BINARY_NAME}" &> /dev/null; then
        echo -e "${YELLOW}⚠ ${BINARY_NAME} is already installed at: $(which ${BINARY_NAME})${NC}"
        read -p "Do you want to reinstall? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 0
        fi
    fi
}

# Create install directory
create_install_dir() {
    mkdir -p "${INSTALL_DIR}"
    if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
        # Automatically add to PATH (don't ask, just do it)
        SHELL_RC=""
        
        # Detect shell and find appropriate RC file
        if [ -n "${ZSH_VERSION}" ]; then
            SHELL_RC="${HOME}/.zshrc"
        elif [ -n "${BASH_VERSION}" ]; then
            SHELL_RC="${HOME}/.bashrc"
            # Fallback to .bash_profile if .bashrc doesn't exist
            if [ ! -f "${SHELL_RC}" ]; then
                SHELL_RC="${HOME}/.bash_profile"
            fi
        else
            # Try common RC files
            for rc in "${HOME}/.profile" "${HOME}/.bashrc" "${HOME}/.zshrc"; do
                if [ -f "${rc}" ]; then
                    SHELL_RC="${rc}"
                    break
                fi
            done
        fi
        
        # Add to PATH if we found an RC file
        if [ -n "${SHELL_RC}" ]; then
            # Check if already added
            if ! grep -q "${INSTALL_DIR}" "${SHELL_RC}" 2>/dev/null; then
                echo "" >> "${SHELL_RC}"
                echo "# Added by Deepwave CLI installer" >> "${SHELL_RC}"
                echo "export PATH=\"\${HOME}/.local/bin:\${PATH}\"" >> "${SHELL_RC}"
                echo -e "${GREEN}✓ Added ${INSTALL_DIR} to PATH in ${SHELL_RC}${NC}"
            fi
        else
            echo -e "${YELLOW}⚠ Could not detect shell RC file.${NC}"
            echo -e "Add this to your shell config:"
            echo -e "${GREEN}export PATH=\"\${HOME}/.local/bin:\${PATH}\"${NC}"
        fi
        
        # Note: User needs to restart shell or source the file
        echo -e "${YELLOW}Note: Restart your terminal or run: source ${SHELL_RC:-~/.zshrc}${NC}"
    fi
}

# Download binary from release
download_binary() {
    if [ "${PLATFORM}" = "macos" ]; then
        BINARY_FILE="${BINARY_NAME}-macos-${ARCH}"
    elif [ "${PLATFORM}" = "linux" ]; then
        BINARY_FILE="${BINARY_NAME}-linux-${ARCH}"
    else
        echo -e "${RED}❌ Unsupported platform: ${PLATFORM}${NC}"
        return 1
    fi
    
    DOWNLOAD_URL="${RELEASE_URL}/${BINARY_FILE}"
    TEMP_FILE=$(mktemp)
    
    echo -e "${GREEN}📥 Downloading ${BINARY_NAME}...${NC}"
    
    if curl -fsSL -o "${TEMP_FILE}" "${DOWNLOAD_URL}"; then
        chmod +x "${TEMP_FILE}"
        mv "${TEMP_FILE}" "${INSTALL_DIR}/${BINARY_NAME}"
        echo -e "${GREEN}✓ Downloaded successfully${NC}"
        return 0
    else
        echo -e "${RED}❌ Download failed. Binary not available for ${PLATFORM}-${ARCH}${NC}"
        echo -e "${YELLOW}Please check available releases:${NC}"
        echo -e "${GREEN}https://github.com/Deepwave-dev/Deepwave-cli/releases${NC}"
        echo -e ""
        echo -e "${YELLOW}Alternatively, install from source:${NC}"
        echo -e "${GREEN}git clone https://github.com/Deepwave-dev/Deepwave-cli.git${NC}"
        echo -e "${GREEN}cd Deepwave-cli && pip install -r cli/requirements.txt${NC}"
        rm -f "${TEMP_FILE}"
        return 1
    fi
}

# Build from source (fallback)
build_from_source() {
    echo -e "${GREEN}🔨 Building from source...${NC}"
    
    # Check for Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python 3 is required but not found${NC}"
        exit 1
    fi
    
    # Check for pip
    if ! command -v pip3 &> /dev/null; then
        echo -e "${RED}❌ pip3 is required but not found${NC}"
        exit 1
    fi
    
    # Get project directory (assuming we're in a git repo or have the source)
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
    
    # Check if we have the source
    if [ ! -f "${PROJECT_ROOT}/cli/deepwave.spec" ]; then
        echo -e "${RED}❌ Source code not found. Cannot build.${NC}"
        echo -e "Please download the source code or use a pre-built binary."
        exit 1
    fi
    
    cd "${PROJECT_ROOT}"
    
    # Install build dependencies
    echo -e "${GREEN}📦 Installing build dependencies...${NC}"
    pip3 install --user pyinstaller
    pip3 install --user -r cli/requirements.txt
    
    # Build
    echo -e "${GREEN}🔨 Building binary...${NC}"
    pyinstaller cli/deepwave.spec --clean --noconfirm
    
    # Install
    if [ -f "dist/${BINARY_NAME}" ]; then
        cp "dist/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
        echo -e "${GREEN}✓ Built and installed successfully${NC}"
    else
        echo -e "${RED}❌ Build failed${NC}"
        exit 1
    fi
}

# Main installation
main() {
    detect_platform
    check_existing
    create_install_dir
    
    # Try to download binary
    if ! download_binary; then
        echo -e "${RED}❌ Installation failed${NC}"
        exit 1
    fi
    
    # Verify installation
    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        echo "deepwave installed"
        echo "Run: deepwave login"
        
        # Check if in PATH
        if command -v "${BINARY_NAME}" &> /dev/null; then
            echo "Run: deepwave login"
        else
            echo ""
            echo "To use 'deepwave' command:"
            echo "  1. Restart your terminal, OR"
            echo "  2. Run: source ~/.zshrc (or ~/.bashrc)"
            echo ""
            echo "Or use full path: ${INSTALL_DIR}/${BINARY_NAME} login"
        fi
    else
        echo -e "${RED}❌ Installation failed${NC}"
        exit 1
    fi
}

main

