#Licensed under GPLV3.
#@hejhdiss(Muhammed Shafin P)
#POC


import hashlib

class InfiniteMapCrypto:
    def __init__(self, key):
        """
        Initializes the system with a variable-length key.
        The 'infinity' comes from the fact that the key dictates the 
        mathematical laws (the map) of the universe for this session.
        """
        self.key = key
        # Use SHA-256 to create a deterministic numeric seed from the string key
        self.seed_hash = int(hashlib.sha256(key.encode()).hexdigest(), 16)
        
        # Derive dynamic system parameters from the seed
        # These change every time you change the key
        self.modulus = 10**12 + (self.seed_hash % 10**9) # Large dynamic modulus
        self.exponent = (self.seed_hash % 7) + 3         # Dynamic exponent (3-9)
        
        # Generate the 'Dynamic Map' for all ASCII characters
        self.char_map = self._generate_dynamic_map()

    def _generate_dynamic_map(self):
        """
        Generates a unique, deterministic 'coordinate' for every character
        based on the user's secret key.
        """
        map_list = []
        for i in range(256):
            # Salt each character index with the main seed to ensure uniqueness
            char_seed = hashlib.sha256(f"{self.seed_hash}-{i}".encode()).hexdigest()
            # Generate a large value for this character
            val = int(char_seed[:12], 16) % (self.modulus // 2)
            map_list.append(val)
        return map_list

    def encrypt_to_numbers(self, plaintext):
        """Returns a list of raw integers."""
        encrypted_values = []
        for char in plaintext:
            x = self.char_map[ord(char)]
            cipher_val = pow(x, self.exponent, self.modulus)
            encrypted_values.append(cipher_val)
        return encrypted_values

    def to_hex(self, num_list):
        """Converts the list of numbers into a formatted Hex string."""
        # Convert each number to hex, strip '0x', and pad to ensure even length
        return ":".join([hex(n)[2:].zfill(10) for n in num_list])

    def to_bytes(self, num_list):
        """Converts the list of numbers into a single raw byte array."""
        byte_output = bytearray()
        for n in num_list:
            # Calculate bytes needed (min 8 bytes for our 10^12 modulus)
            num_bytes = (n.bit_length() + 7) // 8
            byte_output.extend(n.to_bytes(num_bytes, 'big'))
        return bytes(byte_output)

    def decrypt_from_numbers(self, num_list):
        """
        Reverses the math by matching the results against the key-generated map.
        """
        decrypted_chars = []
        for target_cipher in num_list:
            found = False
            for char_code, x in enumerate(self.char_map):
                if pow(x, self.exponent, self.modulus) == target_cipher:
                    decrypted_chars.append(chr(char_code))
                    found = True
                    break
            
            if not found:
                decrypted_chars.append("?") 
                
        return "".join(decrypted_chars)

# --- EXECUTION ---

if __name__ == "__main__":
    user_key = input("Enter your secret key: ")
    user_input = input("Enter string to encrypt: ")

    # Initialize System
    crypto = InfiniteMapCrypto(user_key)

    # 1. Encrypt to Raw Numbers
    raw_numbers = crypto.encrypt_to_numbers(user_input)
    
    # 2. Represent as HEX
    hex_repr = crypto.to_hex(raw_numbers)
    
    # 3. Represent as BYTES
    byte_repr = crypto.to_bytes(raw_numbers)

    print("\n" + "="*50)
    print("ENCRYPTION RESULTS")
    print("="*50)
    print(f"Key Used: {user_key}")
    print(f"Modulus:  {crypto.modulus}")
    print(f"Exponent: {crypto.exponent}")
    print("-" * 50)
    print(f"[HEX REPRESENTATION]:\n{hex_repr}")
    print("-" * 50)
    print(f"[RAW BYTES (Truncated)]: \n{byte_repr[:50]}...")
    print("-" * 50)

    # Decrypt using the raw numbers to show it works
    decrypted = crypto.decrypt_from_numbers(raw_numbers)
    print(f"[DECRYPTED RESULT]: {decrypted}")
    print("="*50)