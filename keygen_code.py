import hashlib
import binascii
import struct
import zlib
import os
from ecdsa import SigningKey, SECP256k1

# Utility functions
def sha1(data):
    """Compute SHA-1 hash of the input data."""
    return hashlib.sha1(data).digest()

def crc32(data):
    """Compute CRC32 checksum of the input data."""
    return zlib.crc32(data) & 0xFFFFFFFF

def pad_to_length(hex_string, length):
    """Pad the hexadecimal string to a specific length."""
    return hex_string.zfill(length)

def generate_keypair():
    """Generate a private and public key pair."""
    priv_key = SigningKey.generate(curve=SECP256k1)
    pub_key = priv_key.get_verifying_key()
    return priv_key, pub_key

def sign_message(priv_key, message):
    """Sign a message with the private key."""
    return priv_key.sign(message)

def generate_rarreg_key(username, license_type):
    """Generate the rarreg.key file."""
    # Generate key pairs for UID and Data3
    priv_key_u, pub_key_u = generate_keypair()
    priv_key_data3, pub_key_data3 = generate_keypair()

    # Convert public keys to hexadecimal format
    temp_pub_key_hex = binascii.hexlify(pub_key_u.to_string()).decode()
    temp_pub_key_hex = pad_to_length(temp_pub_key_hex, 64)
    data0_pub_key_hex = binascii.hexlify(pub_key_data3.to_string()).decode()
    data0_pub_key_hex = pad_to_length(data0_pub_key_hex, 64)
    
    # Calculate signature for UID
    uid = temp_pub_key_hex + data0_pub_key_hex
    uid_hash = sha1(uid.encode())
    uid_signature = sign_message(priv_key_u, uid_hash)
    
    r_uid = int.from_bytes(uid_signature[:32], 'big')
    s_uid = int.from_bytes(uid_signature[32:], 'big')
    
    r_uid_hex = pad_to_length(hex(r_uid)[2:], 60)
    s_uid_hex = pad_to_length(hex(s_uid)[2:], 60)
    
    data1 = temp_pub_key_hex + data0_pub_key_hex + r_uid_hex + s_uid_hex
    
    # Calculate signature for Temp
    temp = temp_pub_key_hex + data0_pub_key_hex + r_uid_hex + s_uid_hex
    temp_hash = sha1(temp.encode())
    temp_signature = sign_message(priv_key_u, temp_hash)
    
    r_temp = int.from_bytes(temp_signature[:32], 'big')
    s_temp = int.from_bytes(temp_signature[32:], 'big')
    
    r_temp_hex = pad_to_length(hex(r_temp)[2:], 60)
    s_temp_hex = pad_to_length(hex(s_temp)[2:], 60)
    
    data2 = r_temp_hex + s_temp_hex
    
    # CRC32 Checksum
    data_for_crc = (data1 + data2).encode()
    checksum = crc32(data_for_crc)
    checksum = 0xFFFFFFFF - checksum
    sz_checksum = str(checksum).zfill(10)
    
    # Final Data String
    data = data1 + data2 + sz_checksum
    
    # Ensure total length of Data is exactly 368 characters
    data = data.ljust(368, '0')  # Pad to ensure correct length
    
    # Format Output
    header = "RAR registration data"
    result = f"{header}\n{username}\n{license_type}\nUID={temp_pub_key_hex}\n"
    
    # Split data into lines of 54 characters
    for i in range(0, len(data), 54):
        result += data[i:i + 54] + "\n"
    
    # Save to file
    file_name = "rarreg.key"
    with open(file_name, "w") as f:
        f.write(result)
    
    # Print the full path of the generated file
    full_path = os.path.abspath(file_name)
    print(f"RAR registration key generated and saved as '{full_path}'.")

# Example usage
username = "User"  # Example username
license_type = "Single PC usage license"  # Example license type
generate_rarreg_key(username, license_type)
