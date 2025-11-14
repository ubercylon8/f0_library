#!/bin/bash
# Build F0RT1KA Results Collector for Windows

set -e

echo "========================================"
echo "F0RT1KA Results Collector - Build Script"
echo "========================================"
echo ""

# Get version from main.go
VERSION=$(grep 'const VERSION' main.go | cut -d'"' -f2)
echo "Building version: $VERSION"
echo ""

# Build for Windows
echo "[1/2] Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -o f0_collector.exe \
    -ldflags "-s -w" \
    .

if [ $? -eq 0 ]; then
    echo "✓ Build successful"

    # Get file size
    SIZE=$(ls -lh f0_collector.exe | awk '{print $5}')
    echo "✓ Binary size: $SIZE"
else
    echo "✗ Build failed"
    exit 1
fi

echo ""
echo "[2/2] Verifying build..."

# Check if file exists and is executable
if [ -f "f0_collector.exe" ]; then
    echo "✓ f0_collector.exe created"
else
    echo "✗ f0_collector.exe not found"
    exit 1
fi

echo ""
echo "========================================"
echo "Build Complete!"
echo "========================================"
echo ""
echo "Output: f0_collector.exe"
echo ""
echo "Next steps:"
echo "  1. Copy f0_collector.exe to Windows endpoint"
echo "  2. Copy collector_config.json to Windows endpoint"
echo "  3. Run: .\\deploy-collector-task.ps1"
echo ""
echo "For manual testing:"
echo "  .\\f0_collector.exe validate"
echo "  .\\f0_collector.exe collect --once --verbose"
echo ""
