#!/bin/bash


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

create_test_files