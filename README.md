# Custom Prime-Based Key-Driven Encryption - Proof of Concept

A novel encryption concept demonstrating key-driven prime mapping with infinite key space possibilities.

## ⚠️ Important Notice

**This is a theoretical proof-of-concept (POC) implementation only.** This code demonstrates that the core concept can work in principle, but it is **NOT intended for production use** or real-world security applications.

The claims made about this encryption system are **theoretical**, not practical. This POC exists solely to show that the fundamental idea is implementable - nothing more.

## About This Project

This repository contains a proof-of-concept implementation of my custom encryption design, which explores:

- Key-driven dynamic prime mapping
- Variable-length keys with no maximum cap
- Deterministic parameter derivation from keys
- Modular exponentiation-based transformation

The full theoretical concept and design philosophy are detailed in my article: [Custom Prime-Based Key-Driven Encryption with Modulus Patterns](https://coderlegion.com/5443/custom-prime-based-key-driven-encryption-with-modulus-patterns)

**Read the article and its comments for complete context** - they explain the theoretical foundations, security model, and various implementation possibilities.

## How It Works (Simplified)

1. **Key Input**: User provides a variable-length secret key
2. **Parameter Derivation**: System generates unique modulus, exponent, and character mappings from the key
3. **Encryption**: Each character maps to a prime-based value, then undergoes modular exponentiation
4. **Output**: Returns encrypted data as hex or byte representation
5. **Decryption**: Reverses the process using the same key-derived parameters

## Usage

```bash
python c.py
```

Enter your secret key and plaintext when prompted. The system will:
- Generate unique encryption parameters from your key
- Encrypt your input
- Display results in hex and byte format
- Demonstrate decryption

## Example

```
Enter your secret key: mySecretKey123
Enter string to encrypt: Hello World

==================================================
ENCRYPTION RESULTS
==================================================
Key Used: mySecretKey123
Modulus:  1000946181578
Exponent: 6
--------------------------------------------------
[HEX REPRESENTATION]:
20dfd2e302:81be257cdf:774bc2d67c:774bc2d67c:adf1a810ad:839c064e36:83e860931a:adf1a810ad:a012f7dd6b:774bc2d67c:b29b60d508
--------------------------------------------------
[RAW BYTES (Truncated)]:
b' \xdf\xd2\xe3\x02\x81\xbe%|\xdfwK\xc2\xd6|wK\xc2\xd6|\xad\xf1\xa8\x10\xad\x83\x9c\x06N6\x83\xe8`\x93\x1a\xad\xf1\xa8\x10\xad\xa0\x12\xf7\xddkwK\xc2\xd6|'...
--------------------------------------------------
[DECRYPTED RESULT]: Hello World
==================================================
```

## Repository

**GitHub**: https://github.com/hejhdiss/custom-encryption-poc

## Licensing

- **Article & Concept**: Licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)
- **Code**: Licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Credits

**Design & Implementation**: Muhammed Shafin P ([@hejhdiss](https://github.com/hejhdiss))

This is my original cryptographic design concept.

## Disclaimer

This is an experimental concept and proof-of-concept code. It has not undergone professional cryptographic review or security auditing. **Do not use this for protecting sensitive data.** For production applications, use established, peer-reviewed cryptographic standards like AES, RSA, or ECC.

The theoretical security claims are based on mathematical assumptions and have not been validated through real-world testing or cryptanalysis.

## Contributing

This is a conceptual POC. If you're interested in the ideas presented here, please read the [full article and discussion](https://coderlegion.com/5443/custom-prime-based-key-driven-encryption-with-modulus-patterns) first.

## Further Reading

For detailed explanation of the theoretical model, security analysis, implementation considerations, and community discussion, see:
- [Main Article](https://coderlegion.com/5443/custom-prime-based-key-driven-encryption-with-modulus-patterns)
- Article comments section (contains important clarifications and additional details)

---

*This project demonstrates that novel cryptographic concepts can be explored and prototyped. The gap between theoretical possibility and practical security is significant and requires extensive professional review.*
