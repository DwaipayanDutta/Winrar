import hashlib
import binascii
import struct
import zlib
import os
from ecdsa import SigningKey, SECP256k1

class RARKeyGenerator:
    """Generates RAR registration keys with ECDSA signatures."""
    
    PUB_KEY_LEN = 64
    SIG_COMPONENT_LEN = 60
    DATA_LINE_LEN = 54
    TOTAL_DATA_LEN = 368
    
    @staticmethod
    def sha1(data: bytes) -> bytes:
        """Compute SHA-1 hash."""
        return hashlib.sha1(data).digest()
    
    @staticmethod
    def crc32(data: bytes) -> str:
        """Compute inverted CRC32 checksum as 10-digit string."""
        checksum = zlib.crc32(data) & 0xFFFFFFFF
        return str(0xFFFFFFFF - checksum).zfill(10)
    
    @staticmethod
    def pad_hex(hex_str: str, length: int) -> str:
        """Pad hex string to specified length."""
        return hex_str.zfill(length)
    
    @staticmethod
    def generate_keypair() -> tuple[SigningKey, bytes]:
        """Generate ECDSA SECP256k1 keypair."""
        priv_key = SigningKey.generate(curve=SECP256k1)
        pub_key = priv_key.get_verifying_key()
        return priv_key, pub_key.to_string()
    
    @staticmethod
    def sign_and_extract_rs(priv_key: SigningKey, message: bytes) -> tuple[str, str]:
        """Sign message and extract r,s components as padded hex."""
        signature = priv_key.sign(message)
        r = int.from_bytes(signature[:32], 'big')
        s = int.from_bytes(signature[32:], 'big')
        return (
            RARKeyGenerator.pad_hex(hex(r)[2:], RARKeyGenerator.SIG_COMPONENT_LEN),
            RARKeyGenerator.pad_hex(hex(s)[2:], RARKeyGenerator.SIG_COMPONENT_LEN)
        )
    
    @classmethod
    def build_uid_signature(cls, uid_pub_key: str, data0_pub_key: str, 
                           uid_priv_key: SigningKey) -> tuple[str, str]:
        """Build UID signature components."""
        uid = uid_pub_key + data0_pub_key
        uid_hash = cls.sha1(uid.encode())
        r_uid, s_uid = cls.sign_and_extract_rs(uid_priv_key, uid_hash)
        return r_uid, s_uid
    
    @classmethod
    def build_temp_signature(cls, uid_pub_key: str, data0_pub_key: str, 
                           r_uid: str, s_uid: str, uid_priv_key: SigningKey) -> tuple[str, str]:
        """Build Temp signature components."""
        temp = uid_pub_key + data0_pub_key + r_uid + s_uid
        temp_hash = cls.sha1(temp.encode())
        r_temp, s_temp = cls.sign_and_extract_rs(uid_priv_key, temp_hash)
        return r_temp, s_temp
    
    @classmethod
    def generate_key_data(cls, username: str, license_type: str) -> str:
        """Generate complete RAR key data."""
        # Generate keypairs
        uid_priv_key, uid_pub_key = cls.generate_keypair()
        _, data0_pub_key = cls.generate_keypair()
        
        # Format public keys
        uid_pub_key_hex = cls.pad_hex(binascii.hexlify(uid_pub_key).decode(), cls.PUB_KEY_LEN)
        data0_pub_key_hex = cls.pad_hex(binascii.hexlify(data0_pub_key).decode(), cls.PUB_KEY_LEN)
        
        # Build signatures
        r_uid, s_uid = cls.build_uid_signature(uid_pub_key_hex, data0_pub_key_hex, uid_priv_key)
        r_temp, s_temp = cls.build_temp_signature(
            uid_pub_key_hex, data0_pub_key_hex, r_uid, s_uid, uid_priv_key
        )
        
        # Assemble data components
        data1 = uid_pub_key_hex + data0_pub_key_hex + r_uid + s_uid
        data2 = r_temp + s_temp
        
        # Calculate checksum and finalize
        data_for_crc = (data1 + data2).encode()
        checksum = cls.crc32(data_for_crc)
        data = (data1 + data2 + checksum).ljust(cls.TOTAL_DATA_LEN, '0')
        
        return cls.format_key_file(username, license_type, data)
    
    @staticmethod
    def format_key_file(username: str, license_type: str, data: str) -> str:
        """Format data into RAR key file format."""
        header = "RAR registration data"
        result = f"{header}\n{username}\n{license_type}\nUID="
        
        # Split data into 54-char lines
        for i in range(0, len(data), RARKeyGenerator.DATA_LINE_LEN):
            result += data[i:i + RARKeyGenerator.DATA_LINE_LEN] + "\n"
        
        return result
    
    @classmethod
    def save_key_file(cls, username: str, license_type: str, output_dir: str = ".") -> str:
        """Generate and save RAR key file."""
        key_content = cls.generate_key_data(username, license_type)
        file_name = "rarreg.key"
        file_path = os.path.join(output_dir, file_name)
        
        os.makedirs(output_dir, exist_ok=True)
        with open(file_path, "w") as f:
            f.write(key_content)
        
        return os.path.abspath(file_path)

# Example usage
if __name__ == "__main__":
    username = "User"
    license_type = "Single PC usage license"
    
    file_path = RARKeyGenerator.save_key_file(username, license_type)
    print(f"RAR registration key generated and saved as '{file_path}'.")
