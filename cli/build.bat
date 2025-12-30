@echo off
REM Build script for Deepwave CLI using PyInstaller (Windows)

echo 🔨 Building Deepwave CLI binary...

REM Get the project root directory
cd /d "%~dp0\.."

REM Check if PyInstaller is installed
where pyinstaller >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ❌ PyInstaller is not installed. Installing...
    pip install pyinstaller
)

REM Install CLI dependencies
echo 📦 Installing dependencies...
pip install -r cli\requirements.txt

REM Build the binary
echo 🔨 Building binary with PyInstaller...
pyinstaller cli\deepwave.spec --clean

REM Check if build was successful
if exist "dist\deepwave.exe" (
    echo ✅ Build successful! Binary created at: dist\deepwave.exe
) else (
    echo ❌ Build failed! Binary not found.
    exit /b 1
)

