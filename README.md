HashWizard 🔍🔐

Advanced Hash Type Detection & Analysis Tool

HashWizard is a powerful Python utility designed to identify and analyze various types of cryptographic hashes and encrypted strings. It is perfect for security researchers, forensic analysts, and penetration testers working in cybersecurity investigations.

CLI Example
Example output showing hash analysis
Features ✨
Multi-Category Detection

    Forensic hashes (MD5, SHA family)

    Password hashes (bcrypt, Argon2, PBKDF2)

    Windows authentication hashes

    Database hashes (MySQL, PostgreSQL)

    Network device hashes (Cisco Type 7/8/9)

    File hashes (ssdeep, TLSH)

Advanced Detection Methods

    Pattern matching with regex

    Entropy analysis

    Character distribution statistics

    Custom validation rules

    Length detection

Enhanced Output

    Confidence level indicators

    Documentation links

    Batch file processing

    Verbose mode for technical details

```markdown
## Installation 🛠️

1. **Requirements**
   - Python 3.8+
   - No external dependencies

2. **Direct Download**
   ```bash
   git clone https://github.com/yourusername/hashwizard.git
   cd hashwizard
   ```

3. **Run the Tool**
   ```bash
   python HashWizard.py [options] [hash_string]
   ```

## Supported Algorithms 📚

| Category           | Supported Hashes/Formats                                   |
|--------------------|-----------------------------------------------------------|
| **Forensics**      | MD5, SHA-1/256/512, CRC32, xxHash                         |
| **Web Security**   | bcrypt, Argon2, PBKDF2, HMAC, JWT                         |
| **Windows**        | LM, NTLM, Domain Cached Credentials                       |
| **Databases**      | MySQL 4.1+, PostgreSQL MD5                                |
| **Network Devices**| Cisco Type 7/8/9, OpenSSL salted formats                  |
| **File Analysis**  | ssdeep, TLSH, Imphash                                     |
| **Cryptography**   | SHA3 variants, BLAKE2/3, Whirlpool, RIPEMD-160            |

## Contributing 🤝

We welcome contributions! Here's how to help:
1. Report false positives/negatives as GitHub Issues
2. Add support for new hash types
3. Improve detection algorithms
4. Expand documentation


## License 📜

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments 🏆

- Inspired by various hash identification tools
- Built with Python's standard library
- Regex patterns from OWASP documentation
- Entropy calculation methods from cryptography research
**Happy Hashing!** 🧙♂️✨
