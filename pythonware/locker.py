# Use argparse to parse command line arguments (operator_public, test_directory, --upload-files, --delete-files)
# For every file in test_directory:
# - generate an ecdsa keypair
# - compute a shared secret with the (file_private, operator_public) pair
# - discard the private key from memory
# - encrypt the file with the shared secret as {filename}.enc
# - append the file_public to the end of the encrypted file
# - optional: send the encrypted file to the operator
# - optional: delete the original file