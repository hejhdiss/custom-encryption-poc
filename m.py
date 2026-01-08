# Licensed under GPLV3.
# @hejhdiss (Muhammed Shafin P)
# Metaclass PoC: DNA-Driven Mapping with Full Diagnostic Output

import hashlib

class MetaclassCrypto:
    def __init__(self, key):
        self.key = key
        
        # 1. SELECT ENGINE (BLAKE2b or SHA256)
        key_sum = sum(key.encode())
        if key_sum % 2 == 0:
            self.engine_name = "blake2b"
            self.selected_hash = hashlib.blake2b
        else:
            self.engine_name = "sha256"
            self.selected_hash = hashlib.sha256
        
        # 2. DNA DERIVATION (The blueprint for all subsequent logic)
        self.dna_hex = self.selected_hash(key.encode()).hexdigest()
        self.dna_int = int(self.dna_hex, 16)
        
        # 3. METACLASS RULE: DATA BIT GRANULARITY (4, 6, 8, or 12 bits)
        granularity_map = {0: 4, 1: 8, 2: 6, 3: 12}
        self.bit_size = granularity_map[self.dna_int % 4]
        
        # 4. METACLASS RULE: MAPPING LOGIC SELECTION (Extracted from DNA)
        self.mapping_logic_id = (self.dna_int >> 4) % 3
        self.mapping_logic_name = ["Pure-Prime", "XOR-Prime Hybrid", "DNA-Offset Stream"][self.mapping_logic_id]
        
        # 5. DYNAMIC NOISE BIT DEPTH (4-16 bits)
        self.noise_bit_depth = ((self.dna_int >> 8) % 13) + 4 
        
        # 6. DERIVE MATH PARAMETERS
        self.modulus = 10**15 + (self.dna_int % 10**12)
        self.exponent = (self.dna_int % 11) + 7
        
        # 7. GENERATE DYNAMIC MAP
        self.map_range = 2**self.bit_size
        self.char_map = list(self._map_generator())

        # 8. NOISE TOKEN DERIVATION
        self.noise_base_seed = hashlib.sha256(f"dynamic-noise-{self.dna_hex}".encode()).digest()

    def _is_prime(self, n):
        if n < 2: return False
        for i in range(2, int(n**0.5) + 1):
            if n % i == 0: return False
        return True

    def _get_nth_prime(self, start_val, n):
        count = 0
        candidate = start_val | 1 
        while count <= n:
            if self._is_prime(candidate):
                if count == n: return candidate
                count += 1
            candidate += 2

    def _map_generator(self):
        base_seed = (self.dna_int % 100000) + 100
        for i in range(self.map_range):
            if self.mapping_logic_id == 0: # Pure Prime
                val = self._get_nth_prime(base_seed, i)
            elif self.mapping_logic_id == 1: # XOR-Prime Hybrid
                xor_factor = (self.dna_int >> (i % 64)) & 0xFF
                val = self._get_nth_prime(base_seed, i ^ xor_factor)
            else: # DNA-Offset
                h = hashlib.blake2b(f"{self.dna_hex}-{i}".encode(), digest_size=16)
                val = int(h.hexdigest(), 16)
            yield val % (self.modulus // 2)

    def _get_noise_for_block(self, block_index):
        h = hashlib.sha256(self.noise_base_seed + str(block_index).encode()).digest()
        raw_val = int.from_bytes(h[:4], 'big')
        return raw_val & ((1 << self.noise_bit_depth) - 1)

    def _string_to_bits(self, text):
        bit_str = "".join(f"{ord(c):08b}" for c in text)
        padding = (self.bit_size - (len(bit_str) % self.bit_size)) % self.bit_size
        bit_str += "0" * padding
        return [int(bit_str[i:i+self.bit_size], 2) for i in range(0, len(bit_str), self.bit_size)]

    def encrypt(self, plaintext):
        slices = self._string_to_bits(plaintext)
        encrypted_blocks = []
        for i, s in enumerate(slices):
            x = self.char_map[s]
            cipher_val = pow(x, self.exponent, self.modulus)
            noise_val = self._get_noise_for_block(i)
            encrypted_blocks.append((cipher_val, noise_val))
        return encrypted_blocks

    def decrypt(self, block_list):
        decrypted_indices = []
        for i, (target_cipher, received_noise) in enumerate(block_list):
            if received_noise != self._get_noise_for_block(i):
                return "INTEGRITY_ERR"
            found = False
            for idx, val in enumerate(self.char_map):
                if pow(val, self.exponent, self.modulus) == target_cipher:
                    decrypted_indices.append(idx)
                    found = True
                    break
            if not found: return "DECRYPTION_ERR"
        bit_str = "".join(f"{idx:0{self.bit_size}b}" for idx in decrypted_indices)
        chars = [chr(int(bit_str[i:i+8], 2)) for i in range(0, (len(bit_str) // 8) * 8, 8)]
        return "".join(chars).rstrip('\x00')

if __name__ == "__main__":
    print("\n" + "#"*60)
    print("AUTHOR: Muhammed Shafin P (@hejhdiss)")
    print("PROJECT: Metaclass Polymorphic Crypto PoC")
    print("#"*60)
    print("!! WARNING: THIS IS A PURELY BASIC PROOF-OF-CONCEPT (PoC) !!")
    print("- This implementation is NOT optimized for speed.")
    print("- It is heavy on system resources (CPU/RAM).")
    print("- This is NOT a real-world production-ready version.")
    print("- Purpose: To demonstrate the functionality of Metaclass Architecture.")
    print("#"*60 + "\n")

    key = input("Enter Secret Key: ")
    text = input("Enter Message: ")
    
    # Initialize session
    crypto = MetaclassCrypto(key)
    
    print("\n" + "="*60)
    print("SESSION DNA & METACLASS GENERATION DETAILS")
    print("="*60)
    print(f"Master DNA (Hex Prefix): {crypto.dna_hex[:16]}...")
    print(f"Primary Engine:          {crypto.engine_name.upper()}")
    print(f"Mapping Universe:        {crypto.mapping_logic_name}")
    print(f"Data Granularity:        {crypto.bit_size}-bit slices")
    print(f"Injected Noise:          {crypto.noise_bit_depth}-bit per block")
    print(f"Dynamic Modulus (M):     {crypto.modulus}")
    print(f"Dynamic Exponent (E):    {crypto.exponent}")
    print("-" * 60)
    
    # Execution
    print("Encrypting... (Resource Intensive Process)")
    enc = crypto.encrypt(text)
    
    # Format and Print FULL Ciphertext in HEX and BINARY
    print("\n[FULL ENCRYPTED DATA - HEXADECIMAL]")
    full_hex = " ".join([f"{hex(v)[2:].upper()}:{hex(n)[2:].upper()}" for v, n in enc])
    print(full_hex)

    print("\n[FULL ENCRYPTED DATA - BINARY]")
    # Showing each block's data and noise bits
    for i, (val, noise) in enumerate(enc):
        b_val = bin(val)[2:]
        b_noise = bin(noise)[2:].zfill(crypto.noise_bit_depth)
        print(f"B{i}: DATA({b_val}) NOISE({b_noise})")

    print("\n" + "-" * 60)
    print("Decrypting... (Verifying Integrity)")
    dec = crypto.decrypt(enc)
    print(f"DECRYPTED RESULT: {dec}")

    print("="*60)
