# Arguments (argparser):
# - encrypted_directory
# For every .enc file in the encrypted_directory:
# - read the public key from the end of the file
# - compute the ecdsa shared secret with (operator_private, file_public)
# - decrypt the file using the shared secret
# - save the decrypted file as {filename}.dec (instead of .enc)
