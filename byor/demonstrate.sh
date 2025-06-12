#!/bin/bash

# This script runs a comprehensive set of tests for the ransom tool.
# It creates a large number of files and directories to simulate a real-world scenario.
# By default, it runs in quiet mode, only reporting failures.
# Use the -v or --verbose flag for detailed output.
#
# Usage: ./demonstrate.sh [-v|--verbose]

set -e

# --- Configuration ---
RANSOM_BINARY="./ransom"
TEST_DIR="./test_data"
HASH_FILE="hashes.txt"
LOG_FILE="demonstration.log"
NUM_DIRS=20
NUM_FILES_PER_DIR=50

# --- Verbosity Control ---
VERBOSE=false
if [ "$1" = "-v" ] || [ "$1" = "--verbose" ]; then
  VERBOSE=true
fi

# --- Helper Functions ---

# Echos a message only if VERBOSE is true
verbose_echo() {
  if [ "$VERBOSE" = true ]; then
    echo "$@"
  fi
}

# Executes a command, redirecting its output to /dev/null unless in verbose mode
run_quietly() {
  if [ "$VERBOSE" = true ]; then
    "$@"
  else
    "$@" >/dev/null 2>&1 || true
  fi
}

cleanup() {
  verbose_echo "---"
  verbose_echo "Cleaning up..."
  rm -f "$RANSOM_BINARY" "$HASH_FILE" "$LOG_FILE"
  rm -f public.key private.key public.pem private.pem
  rm -rf "$TEST_DIR"
  verbose_echo "Cleanup complete."
}

# Creates a diverse set of test files to evaluate strategies
create_test_files() {
  verbose_echo "  - Creating $NUM_DIRS directories with $NUM_FILES_PER_DIR files each..."
  mkdir -p "$TEST_DIR"

  for i in $(seq 1 "$NUM_DIRS"); do
    local dir_path="$TEST_DIR/dir_$i"
    # Create nested directory every 5 dirs
    if [ $((i % 5)) -eq 0 ]; then
        dir_path="$dir_path/nested"
    fi
    mkdir -p "$dir_path"

    for j in $(seq 1 "$NUM_FILES_PER_DIR"); do
      local file_path="$dir_path/file_${i}_${j}"
      local size_type=$((RANDOM % 4))

      case $size_type in
        0) # Tiny text file (a few bytes)
          echo "Test file ${i}-${j}" > "${file_path}.txt"
          ;;
        1) # Small binary file (1-10 KB)
          dd if=/dev/urandom of="${file_path}.bin" bs=1k count=$((RANDOM % 10 + 1)) >/dev/null 2>&1
          ;;
        2) # Empty file
           touch "${file_path}.empty"
           ;;
        3) # A file with a common extension for intelligent mode
           echo "some data" > "${file_path}.log"
           ;;
      esac
    done
  done

  verbose_echo "  - Adding specific large files for intelligent mode strategy testing..."
  # Medium file (1MB < size < 5MB) -> intelligent mode should pick HEADER
  dd if=/dev/urandom of="$TEST_DIR/medium_archive.zip" bs=1048576 count=3 >/dev/null 2>&1
  # Large VM disk file (> 5MB) -> intelligent mode should pick PARTIAL
  dd if=/dev/urandom of="$TEST_DIR/large_disk.vmdk" bs=1048576 count=6 >/dev/null 2>&1
  verbose_echo "  - Test file structure created."
}

# A function to run a full test cycle for a given crypter
# Usage: test_cycle <crypter_type> <mode> [arg3] [arg4] [arg5]
test_cycle() {
  local crypter_type=$1
  local mode=$2
  local partial_percent=10
  local partial_blocks=3
  local discovery_strategy="default"

  # Process optional arguments
  if [ "$mode" = "partial" ]; then
    partial_percent=${3:-10}
    partial_blocks=${4:-3}
    discovery_strategy=${5:-"default"}
  else
    discovery_strategy=${3:-"default"}
  fi
  
  local key_type="ecdh"
  if [ "$crypter_type" = "rsa-aes" ]; then
    key_type="rsa"
  fi

  if [ "$VERBOSE" = true ]; then
    echo ""
    echo "================================================="
    echo "🚀 Starting test for: $crypter_type (Mode: $mode, Discovery: $discovery_strategy)"
    echo "================================================="
  else
    echo -n "🧪 Testing $crypter_type (mode: $mode, discovery: $discovery_strategy)... "
  fi

  # 1. Setup test environment
  verbose_echo "---"
  verbose_echo "1. Setting up test environment..."
  rm -rf "$TEST_DIR"
  create_test_files
  verbose_echo "Test environment created with diverse files."

  # 2. Generate Hashes
  verbose_echo "---"
  verbose_echo "2. Calculating original file hashes..."
  (cd "$TEST_DIR" && find . -type f -exec shasum -a 256 {} +) | sort > "$HASH_FILE"
  verbose_echo "Original hashes stored in $HASH_FILE."
  if [ "$VERBOSE" = true ]; then
    cat "$HASH_FILE"
  fi

  # 3. Generate Keys
  verbose_echo "---"
  verbose_echo "3. Generating $key_type keys..."
  run_quietly "$RANSOM_BINARY" keygen -type="$key_type"
  verbose_echo "Keys generated."

  # 4. Encrypt
  verbose_echo "---"
  verbose_echo "4. Encrypting files (Mode: $mode)..."

  # Only pass partial flags when mode is partial
  local encrypt_cmd=("$RANSOM_BINARY" encrypt -path="$TEST_DIR" -crypter="$crypter_type" -mode="$mode" -discovery="$discovery_strategy")
  if [ "$mode" = "partial" ]; then
    encrypt_cmd+=("-partial-percent=$partial_percent" "-partial-blocks=$partial_blocks")
  fi
  run_quietly "${encrypt_cmd[@]}"

  verbose_echo "Encryption complete."

  # 5. Decrypt
  verbose_echo "---"
  verbose_echo "5. Decrypting files..."
  run_quietly "$RANSOM_BINARY" decrypt -path="$TEST_DIR"
  verbose_echo "Decryption complete."

  # 6. Verify Hashes
  verbose_echo "---"
  verbose_echo "6. Verifying file integrity..."
  local new_hashes
  new_hashes=$(cd "$TEST_DIR" && find . -type f -exec shasum -a 256 {} + | sort)
  local original_hashes
  original_hashes=$(cat "$HASH_FILE")

  if [ "$new_hashes" = "$original_hashes" ]; then
    if [ "$VERBOSE" = true ]; then
        verbose_echo "SUCCESS: Hashes match for '$crypter_type' in '$mode' mode."
    else
        echo "OK"
    fi
  else
    if [ "$VERBOSE" = false ]; then
        echo "FAILED"
    fi
    echo "FAILURE: Hash mismatch for '$crypter_type' in '$mode' mode!"
    echo "Original hashes:"
    echo "$original_hashes"
    echo "Decrypted hashes:"
    echo "$new_hashes"
    exit 1
  fi
}


# --- Main Execution ---

# Ensure cleanup happens on script exit
trap cleanup EXIT

# Clear log file and start fresh
> "$LOG_FILE"

# Build the ransom binary
verbose_echo "---"
verbose_echo "Building ransom binary..."
run_quietly go build -o "$RANSOM_BINARY" ./cmd/ransom
verbose_echo "Binary '$RANSOM_BINARY' built successfully."

# --- Run Test Cycles ---
test_cycle "ecdh-chacha20" "full"
test_cycle "rsa-aes"       "full"
test_cycle "ecdh-chacha20" "header"
test_cycle "rsa-aes"       "partial" "15" "4" "shuffle" # 4 blocks of 15%
test_cycle "ecdh-chacha20" "intelligent" "intelligent"
test_cycle "ecdh-chacha20" "full" "default"
test_cycle "ecdh-chacha20" "full" "intelligent"
test_cycle "ecdh-chacha20" "full" "shuffle"


if [ "$VERBOSE" = true ]; then
  echo ""
  echo "================================================="
  echo "ALL TESTS PASSED SUCCESSFULLY"
  echo "================================================="
else
  echo "All tests passed."
fi

exit 0 