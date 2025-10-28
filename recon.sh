#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# Banner
print_banner() {
    echo -e "${BLUE}"
    cat << "BANNER"
    ____  _      _    _           _   _          _   _             
   |  _ \| |    | |  | |         | | | |        | | | |            
   | |_) | | ___| |__| | __ _ ___| |_| |__   ___| |_| |_ ___ _ __  
   |  _ <| |/ _ \  __  |/ _` / __| __| '_ \ / _ \ __| __/ _ \ '_ \ 
   | |_) | |  __/ |  | | (_| \__ \ |_| | | |  __/ |_| ||  __/ | | |
   |____/|_|\___|_|  |_|\__,_|___/\__|_| |_|\___|\__|\__\___|_| |_|
   
                   Advanced Reconnaissance Suite v2.0
BANNER
    echo -e "${NC}"
}

print_banner

# Check if virtual environment exists and activate
if [ -d "recon_env" ]; then
    echo -e "${YELLOW}[INFO] Activating virtual environment...${NC}"
    source recon_env/bin/activate
else
    echo -e "${YELLOW}[INFO] Virtual environment not found. Using system Python.${NC}"
    echo -e "${YELLOW}[INFO] Run ./install.sh to set up virtual environment.${NC}"
fi

# Check if Python script exists
if [ ! -f "blackhat_recon.py" ]; then
    echo -e "${RED}[ERROR] blackhat_recon.py not found!${NC}"
    echo "Please ensure you're in the correct directory."
    exit 1
fi

# Function to check dependencies
check_dependency() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}[ERROR] $1 not found!${NC}"
        echo "Run ./install.sh to install dependencies."
        return 1
    fi
    return 0
}

# Check critical dependencies
echo -e "${YELLOW}[INFO] Checking dependencies...${NC}"

critical_deps=("python3" "nmap")
for dep in "${critical_deps[@]}"; do
    if ! check_dependency "$dep"; then
        exit 1
    fi
done

# Check optional dependencies
optional_deps=("subfinder" "amass" "httpx" "nuclei")
for dep in "${optional_deps[@]}"; do
    if ! command -v $dep &> /dev/null; then
        echo -e "${YELLOW}[WARNING] $dep not found. Some features may be limited.${NC}"
        echo -e "${YELLOW}[INFO] Run ./install.sh to install all tools.${NC}"
    fi
done

# Help function
show_help() {
    echo -e "${CYAN}Usage: $0 [OPTIONS]${NC}"
    echo ""
    echo -e "${YELLOW}Target Options:${NC}"
    echo "  -u, --url <target>    Single target URL or domain"
    echo "  -f, --file <file>     File containing multiple targets"
    echo ""
    echo -e "${YELLOW}Scan Options:${NC}"
    echo "  -m, --mode <mode>     Scan mode: quick, deep, stealth (default: quick)"
    echo "  -t, --threads <num>   Number of threads (default: 10)"
    echo "  -o, --output <dir>    Output directory (default: ./recon_results)"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 -u example.com"
    echo "  $0 -u example.com -m deep -t 20"
    echo "  $0 -f targets.txt -m quick"
    echo "  $0 -u example.com -o /path/to/results"
    echo ""
    echo -e "${YELLOW}Advanced usage with Python directly:${NC}"
    echo "  python3 blackhat_recon.py -u example.com --mode deep"
    echo "  python3 blackhat_recon.py -f targets.txt --threads 15"
}

# Parse command line arguments
if [ $# -eq 0 ]; then
    show_help
    exit 1
fi

# Convert long options to short ones
for arg in "$@"; do
    shift
    case "$arg" in
        --url) set -- "$@" "-u" ;;
        --file) set -- "$@" "-f" ;;
        --mode) set -- "$@" "-m" ;;
        --threads) set -- "$@" "-t" ;;
        --output) set -- "$@" "-o" ;;
        --help) set -- "$@" "-h" ;;
        *) set -- "$@" "$arg" ;;
    esac
done

# Process arguments
while getopts "u:f:m:t:o:h" opt; do
    case $opt in
        u) TARGET="$OPTARG" ;;
        f) FILE="$OPTARG" ;;
        m) MODE="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

# Build command
CMD="python3 blackhat_recon.py"

if [ ! -z "$TARGET" ]; then
    CMD="$CMD -u \"$TARGET\""
elif [ ! -z "$FILE" ]; then
    if [ ! -f "$FILE" ]; then
        echo -e "${RED}[ERROR] File not found: $FILE${NC}"
        exit 1
    fi
    CMD="$CMD -f \"$FILE\""
else
    echo -e "${RED}[ERROR] No target specified. Use -u or -f.${NC}"
    show_help
    exit 1
fi

if [ ! -z "$MODE" ]; then
    CMD="$CMD -m $MODE"
fi

if [ ! -z "$THREADS" ]; then
    CMD="$CMD -t $THREADS"
fi

if [ ! -z "$OUTPUT" ]; then
    CMD="$CMD -o \"$OUTPUT\""
fi

# Execute the command
echo -e "${GREEN}[INFO] Starting reconnaissance...${NC}"
echo -e "${CYAN}[COMMAND] $CMD${NC}"
echo -e "${YELLOW}[INFO] Results will be saved in: ${OUTPUT:-./recon_results}${NC}"
echo ""

eval $CMD

# Deactivate virtual environment if it was activated
if [ -d "recon_env" ]; then
    deactivate 2>/dev/null
fi
