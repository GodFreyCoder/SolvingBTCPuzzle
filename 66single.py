import hashlib
import ecdsa
import base58
import random
import re

# ANSI color escape codes
CYAN = '\033[96m'
YELLOW = '\033[93m'
RED = '\033[91m'
GREEN = '\033[92m'
PINK = '\033[95m'
RESET = '\033[0m'  # Reset color to default

# Define the range of private keys
start_hex = "000000000000000000000000000000000000000000000002000000028650a528"
end_hex = "000000000000000000000000000000000000000000000003ffffffffffffffff"

start_int = int(start_hex, 16)
end_int = int(end_hex, 16)

# Define the target pattern
target_pattern = "13zb1hQbWVsc2"
target_regex = re.compile(f'^{target_pattern}', re.IGNORECASE)

# Counter for the number of private keys checked
checked_count = 0

# Function to generate compressed address for a given private key
def generate_address(private_key):
    private_key_hex = hex(private_key)[2:].zfill(64)  # Convert to hex and zero fill to 64 characters
    private_key_bytes = bytes.fromhex(private_key_hex)

    # Get the public key
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    public_key_compressed = signing_key.verifying_key.to_string("compressed")  # Compressed public key

    # Compute the hash of the public key
    sha256_hash = hashlib.sha256(public_key_compressed)
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash.digest())
    hash_bytes = ripemd160_hash.digest()

    # Add the version byte (0x00 for mainnet)
    version_byte = b'\x00'
    hash_with_version = version_byte + hash_bytes

    # Calculate the checksum
    checksum = hashlib.sha256(hashlib.sha256(hash_with_version).digest()).digest()[:4]

    # Concatenate the hash and checksum
    binary_address = hash_with_version + checksum

    # Convert the binary address to base58
    address = base58.b58encode(binary_address).decode()

    return private_key_hex, address

# Function to check if address matches the target pattern
def check_address(result):
    global checked_count  # Declare checked_count as global to use it in this function
    private_key_hex, address = result
    if target_regex.match(address):
        print(f"{GREEN}Vanity address found for pattern '{target_pattern}'!{RESET}")
        print(f"{GREEN}Checked Count: {checked_count}{RESET}")
        print(f"{YELLOW}Private Key Hex: {private_key_hex}{RESET}")
        print(f"{PINK}Compressed Address: {address}{RESET}")

        # Write the result to the file
        with open('vanity_results.txt', 'a') as result_file:
            result_file.write(f"Pattern: {target_pattern}\n")
            result_file.write(f"Private Key Hex: {private_key_hex}\n")
            result_file.write(f"Compressed Address: {address}\n")
            result_file.write("-----------------------------------------------\n")
        return True
    else:
        print(f"Checking...{RED}{checked_count}{RESET} | Compressed: {CYAN}{address}{RESET}  ")
        print(f"PrivateKey:{YELLOW}{private_key_hex}{RESET}")
        return False

# Ask for search mode
search_mode = input("Enter search mode (1 for sequential, 2 for random): ")
if search_mode == "1":
    sequential_mode = True
elif search_mode == "2":
    sequential_mode = False
else:
    print("Invalid search mode. Exiting.")
    exit()

# Generate and check addresses
while True:
    if sequential_mode:
        private_key = start_int + checked_count  # Incremental search in sequential mode
    else:
        private_key = random.randint(start_int, end_int)  # Random search in random mode

    result = generate_address(private_key)
    checked_count += 1
    if check_address(result):
        break

print(f"{GREEN}Done.{RESET}")
