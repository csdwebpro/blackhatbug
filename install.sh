#!/bin/bash

echo -e "\033[1;34m"
cat << "BANNER"
    ____  _      _    _           _   _          _   _             
   |  _ \| |    | |  | |         | | | |        | | | |            
   | |_) | | ___| |__| | __ _ ___| |_| |__   ___| |_| |_ ___ _ __  
   |  _ <| |/ _ \  __  |/ _` / __| __| '_ \ / _ \ __| __/ _ \ '_ \ 
   | |_) | |  __/ |  | | (_| \__ \ |_| | | |  __/ |_| ||  __/ | | |
   |____/|_|\___|_|  |_|\__,_|___/\__|_| |_|\___|\__|\__\___|_| |_|
   
                   Advanced Reconnaissance Suite v2.0
                         Installation Script
BANNER
echo -e "\033[0m"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "\033[1;31m[ERROR] Please do not run as root. Run as normal user.\033[0m"
   exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}[INFO] Starting installation...${NC}"

# Update system packages
echo -e "${YELLOW}[INFO] Updating system packages...${NC}"
sudo apt update && sudo apt upgrade -y

# Install system dependencies
echo -e "${YELLOW}[INFO] Installing system dependencies...${NC}"
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    nmap \
    whois \
    dnsutils \
    jq \
    curl \
    wget \
    libnss3 \
    libxss1 \
    libasound2 \
    libxtst6 \
    libgtk-3-0

# Create virtual environment
echo -e "${YELLOW}[INFO] Creating Python virtual environment...${NC}"
python3 -m venv recon_env
source recon_env/bin/activate

# Install Python packages
echo -e "${YELLOW}[INFO] Installing Python packages...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}[INFO] Installing Go language...${NC}"
    wget -q https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:~/go/bin
    rm go1.21.0.linux-amd64.tar.gz
    echo -e "${GREEN}[SUCCESS] Go installed successfully${NC}"
else
    echo -e "${GREEN}[INFO] Go is already installed${NC}"
fi

# Reload bashrc
source ~/.bashrc

# Install Go security tools
echo -e "${YELLOW}[INFO] Installing Go security tools...${NC}"
export PATH=$PATH:/usr/local/go/bin:~/go/bin

go_tools=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/OWASP/Amass/v3/...@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/ffuf/ffuf@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
)

for tool in "${go_tools[@]}"; do
    echo -e "${CYAN}[INSTALL] Installing: $tool${NC}"
    go install $tool
done

# Update nuclei templates
echo -e "${YELLOW}[INFO] Updating Nuclei templates...${NC}"
~/go/bin/nuclei -update-templates

# Make scripts executable
chmod +x recon.sh blackhat_recon.py

# Create config directory
mkdir -p config
if [ -f ".env.example" ]; then
    cp .env.example config/.env.example
fi

# Create results directory
mkdir -p recon_results

echo -e "${GREEN}"
echo "=================================================="
echo "🎉 Installation Completed Successfully!"
echo "=================================================="
echo -e "${NC}"
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Source your bashrc: ${CYAN}source ~/.bashrc${NC}"
echo "2. Activate virtual env: ${CYAN}source recon_env/bin/activate${NC}"
echo "3. Run the tool: ${CYAN}./recon.sh -u example.com${NC}"
echo ""
echo -e "${YELLOW}Available commands:${NC}"
echo "  ./recon.sh -u example.com              # Quick scan"
echo "  ./recon.sh -u example.com -m deep      # Deep scan"
echo "  python3 blackhat_recon.py -u example.com # Direct Python"
echo ""
echo -e "${YELLOW}Configure API keys in config/.env for enhanced features${NC}"
