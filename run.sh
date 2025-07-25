#!/bin/bash

# Colors for better output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

BINDIR="bin"
TOOLS=("setup" "key_generator" "encryptor" "decryptor" "create_policy")

# Function to build all tools
function build {
  echo -e "${BLUE}Building tools...${NC}"
  mkdir -p $BINDIR
  go mod tidy

  for tool in "${TOOLS[@]}"; do
    echo -e "Building $tool..."
    go build -o "$BINDIR/$tool" "cmd/$tool/main.go"
    if [ $? -ne 0 ]; then
      echo -e "${RED}Failed to build $tool${NC}"
      exit 1
    fi
  done

  echo -e "Building demo..."
  go build -o "$BINDIR/demo" main.go
  if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to build demo${NC}"
    exit 1
  fi

  echo -e "${GREEN}Build completed successfully${NC}"
}

# Function to check if tools are built
function check_build {
  for tool in "${TOOLS[@]}"; do
    if [ ! -f "$BINDIR/$tool" ]; then
      echo -e "${BLUE}Tools not built. Building now...${NC}"
      build
      return
    fi
  done
}

# Function to run the full demo flow
function run_all {
  check_build

  echo -e "${BLUE}Running full demo flow...${NC}"

  "$BINDIR/setup"
  echo ""

  "$BINDIR/key_generator"
  echo ""

  "$BINDIR/decryptor" --mode=verify-key
  echo ""

  "$BINDIR/encryptor"
  echo ""

  "$BINDIR/decryptor" --mode=verify-ciphertext
  echo ""

  "$BINDIR/decryptor" --mode=decrypt
  echo ""

  echo -e "${GREEN}Full flow completed successfully${NC}"
}

# Function to clean build artifacts
function clean {
  echo -e "${BLUE}Cleaning build artifacts...${NC}"
  rm -rf "$BINDIR"
  echo -e "${GREEN}Clean completed${NC}"
}

# Show help
function show_help {
  echo -e "${BLUE}Usage: ./run.sh [command] [arguments]${NC}"
  echo ""
  echo "Commands:"
  echo "  build                     - Build all tools"
  echo "  setup [args]              - Run setup with optional arguments"
  echo "  keygen [args]             - Run key generator with optional arguments"
  echo "  encrypt [args]            - Run encryptor with optional arguments"
  echo "  decrypt [args]            - Run decryption with optional arguments"
  echo "  verify-key [args]         - Verify key with optional arguments"
  echo "  verify-ciphertext [args]  - Verify ciphertext with optional arguments"
  echo "  gen-tests [args]          - Generate tests with optional arguments"
  echo "  all                       - Run full demo flow"
  echo "  clean                     - Clean build artifacts"
  echo "  help                      - Show this help message"
  echo ""
  echo "Examples:"
  echo "  ./run.sh build"
  echo "  ./run.sh setup -h"
  echo "  ./run.sh keygen --verbose"
  echo "  ./run.sh all"
}

# Main script logic
case "$1" in
  "build")
    build
    ;;

  "setup")
    check_build
    shift
    "$BINDIR/setup" "$@"
    ;;

  "keygen")
    check_build
    shift
    "$BINDIR/key_generator" "$@"
    ;;

  "encrypt")
    check_build
    shift
    "$BINDIR/encryptor" "$@"
    ;;

  "decrypt")
    check_build
    shift
    "$BINDIR/decryptor" --mode=decrypt "$@"
    ;;

  "verify-key")
    check_build
    shift
    "$BINDIR/decryptor" --mode=verify-key "$@"
    ;;

  "verify-ciphertext")
    check_build
    shift
    "$BINDIR/decryptor" --mode=verify-ciphertext "$@"
    ;;
  "gen-tests")
      check_build
      go build -o "$BINDIR/gen_test" cmd/gen_test/main.go
      if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to build gen_test${NC}"
        exit 1
      fi
      "$BINDIR/gen_test" "$@"
      ;;
  "benchmark")
      check_build
      shift
      mkdir -p cmd/benchmark
      go build -o "$BINDIR/benchmark" cmd/benchmark/main.go
      if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to build benchmark tool${NC}"
        exit 1
      fi
      # Default to using test_info.json in the in/tests directory if no argument is provided
      test_info="${1:-in/tests/test_info.json}"
      "$BINDIR/benchmark" "$test_info"
      ;;

  "all")
    run_all
    ;;

  "clean")
    clean
    ;;

  "help"|"--help"|"-h")
    show_help
    ;;

  "")
    run_all
    ;;

  *)
    echo -e "${RED}Unknown command: $1${NC}"
    show_help
    exit 1
    ;;
esac

exit 0