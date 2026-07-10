#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="$SCRIPT_DIR/venv"
VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"
REQUIREMENTS_FILE="$SCRIPT_DIR/requirements.txt"

print_banner() {
    echo "========================================="
    echo "    ?????? - ????"
    echo "========================================="
    echo
}

print_banner

if [ ! -f "$REQUIREMENTS_FILE" ]; then
    echo "?? requirements.txt?$REQUIREMENTS_FILE"
    exit 1
fi

if [ ! -x "$VENV_PYTHON" ] || [ ! -x "$VENV_PIP" ]; then
    echo "???????????$VENV_DIR"
    echo "?????????"
    echo "  python3 -m venv venv"
    echo "  source venv/bin/activate"
    echo "  pip install -r requirements.txt"
    exit 1
fi

PYTHON_VERSION="$($VENV_PYTHON --version 2>&1)"
echo "Python ??: $PYTHON_VERSION"
echo

echo "??/?? Python ??..."
"$VENV_PIP" install -r "$REQUIREMENTS_FILE"

if [ "$EUID" -ne 0 ]; then
    echo
    echo "??: ???? root ???????????????traceroute ????????"
    echo "????: sudo ./start.sh"
    echo
fi

echo "??????..."
mkdir -p servers static templates

if [ ! -f "$SCRIPT_DIR/templates/index.html" ] && [ -d "$SCRIPT_DIR/templates_example" ]; then
    echo "??????..."
    cp -r "$SCRIPT_DIR/templates_example"/* "$SCRIPT_DIR/templates/" 2>/dev/null || true
fi

echo
echo "????..."
echo "????: http://localhost:5000"
echo

exec "$VENV_PYTHON" "$SCRIPT_DIR/app.py"
