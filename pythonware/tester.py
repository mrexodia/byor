# Arguments (argparser):
# - directory
# For every file that does not end with .enc or .dec in the directory:
# - sha256 the file
# - sha256 the file.dec
# - compare the two sha256 hashes, assert they are equal