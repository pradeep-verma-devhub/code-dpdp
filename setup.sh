#!/usr/bin/env bash
# ==============================================================================
# code-dpdp | One-Click Automated Setup & Installation Script (Linux & macOS)
# India Digital Personal Data Protection Act 2023 & DPDP Rules 2025 Scanner
# ==============================================================================

set -e

# ANSI Color codes
BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
RESET="\033[0m"

echo -e "${BOLD}${CYAN}"
echo "=================================================================="
echo "   🛡️   CODE-DPDP: Automated Installation & Setup (Linux/macOS)   "
echo "   India Digital Personal Data Protection Act 2023 & Rules 2025   "
echo "=================================================================="
echo -e "${RESET}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# Step 1: Detect Python 3
echo -e "${BOLD}[1/5] Detecting Python 3 environment...${RESET}"
PYTHON_CMD=""
for cmd in python3 python; do
    if command -v "$cmd" >/dev/null 2>&1; then
        PY_VER=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
        PY_MAJOR=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null || true)
        PY_MINOR=$("$cmd" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || true)
        if [ "$PY_MAJOR" = "3" ] && [ "$PY_MINOR" -ge "10" ]; then
            PYTHON_CMD="$cmd"
            echo -e "${GREEN}✓ Found Python $PY_VER ($cmd)${RESET}"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo -e "${RED}[!] Error: Python 3.10 or higher is required.${RESET}"
    echo "Please install Python 3.10+ using: sudo apt install python3 python3-venv (Ubuntu/Debian) or brew install python (macOS)."
    exit 1
fi

# Step 2: Create Python Virtual Environment (.venv)
echo -e "${BOLD}[2/5] Setting up isolated Python virtual environment (.venv)...${RESET}"
if [ ! -d ".venv" ]; then
    "$PYTHON_CMD" -m venv .venv
    echo -e "${GREEN}✓ Created virtual environment in .venv${RESET}"
else
    echo -e "${GREEN}✓ Existing .venv detected${RESET}"
fi

# Activate virtualenv
source .venv/bin/activate

# Upgrade pip and install requirements
echo -e "${BOLD}[3/5] Installing Python dependencies from requirements.txt...${RESET}"
pip install --upgrade pip --quiet
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt --quiet
    echo -e "${GREEN}✓ Python dependencies successfully installed.${RESET}"
else
    echo -e "${YELLOW}[!] Warning: requirements.txt not found. Installing core packages...${RESET}"
    pip install rich reportlab pyyaml requests pytest python-dotenv pillow --quiet
fi

# Step 3: Check Node.js / npm (Optional for Node tooling)
echo -e "${BOLD}[4/5] Checking Node.js environment (optional)...${RESET}"
if command -v npm >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Found npm. Installing package dependencies...${RESET}"
    npm install --no-audit --no-fund --quiet >/dev/null 2>&1 || true
else
    echo -e "${YELLOW}[-] Node/npm not found. Python standalone engine will be used (fully functional).${RESET}"
fi

# Step 4: Configure Executables and Global CLI Command
echo -e "${BOLD}[5/5] Configuring command-line executable...${RESET}"
chmod +x "$ROOT_DIR/bin/code-dpdp"
chmod +x "$ROOT_DIR/start.sh"

# Create local symlink in root directory
ln -sf "$ROOT_DIR/bin/code-dpdp" "$ROOT_DIR/code-dpdp"

# Install into user PATH (~/.local/bin)
USER_BIN="$HOME/.local/bin"
mkdir -p "$USER_BIN"
ln -sf "$ROOT_DIR/bin/code-dpdp" "$USER_BIN/code-dpdp"
echo -e "${GREEN}✓ Linked executable to $USER_BIN/code-dpdp${RESET}"

# Verification test
echo ""
echo -e "${BOLD}[*] Verifying installation with self-test...${RESET}"
"$ROOT_DIR/bin/code-dpdp" --version

echo ""
echo -e "${BOLD}${GREEN}=================================================================="
echo "   🎉 CODE-DPDP Successfully Installed and Ready to Use!          "
echo "==================================================================${RESET}"
echo ""
echo -e "You can now run ${BOLD}code-dpdp${RESET} from anywhere in your terminal!"
echo ""
echo -e "${BOLD}Quick Start Commands:${RESET}"
echo -e "  ${CYAN}code-dpdp scan .${RESET}                   Scan current directory for DPDP non-compliance"
echo -e "  ${CYAN}code-dpdp scan . --pdf report.pdf${RESET}  Generate official executive PDF report"
echo -e "  ${CYAN}code-dpdp rag \"parental consent\"${RESET}   Query the complete DPDP Act 2023 rulebook"
echo -e "  ${CYAN}code-dpdp pii .${RESET}                    Scan codebase for Aadhaar, PAN & credentials"
echo -e "  ${CYAN}code-dpdp consent .${RESET}                Audit consent mechanisms & SARAL compliance"
echo -e "  ${CYAN}code-dpdp egress .${RESET}                 Inspect third-party trackers & data exfiltration"
echo -e "  ${CYAN}code-dpdp penalty .${RESET}                Compute financial liability under Schedule"
echo -e "  ${CYAN}code-dpdp patch . --patches out/${RESET}   Generate git patches for automated fixes"
echo ""

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo -e "${YELLOW}Note: To run 'code-dpdp' directly without ./ from any folder, add this to your ~/.bashrc or ~/.zshrc:${RESET}"
    echo -e "  ${BOLD}export PATH=\"\$HOME/.local/bin:\$PATH\"${RESET}"
    echo ""
fi
