#!/bin/bash
# Build script for Deepwave CLI using PyInstaller

set -e

echo "🔨 Building Deepwave CLI binary..."

# Get the project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Check if PyInstaller is installed
if ! command -v pyinstaller &> /dev/null; then
    echo "❌ PyInstaller is not installed. Installing..."
    pip install pyinstaller
fi

# Install CLI dependencies
echo "📦 Installing dependencies..."
pip install -r cli/requirements.txt

# Build the binary
echo "🔨 Building binary with PyInstaller..."
pyinstaller cli/deepwave.spec --clean

# Check if build was successful
if [ -f "dist/deepwave" ]; then
    echo "✅ Build successful! Binary created at: dist/deepwave"
    echo "📏 Binary size: $(du -h dist/deepwave | cut -f1)"
else
    echo "❌ Build failed! Binary not found."
    exit 1
fi

