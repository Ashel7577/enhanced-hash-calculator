# Enhanced Hash Calculator

An advanced Python-based hash tool for penetration testing with capabilities beyond basic hashing:
- Standard hash calculation (MD5, SHA-1, SHA-2, SHA-3)
- Hash type identification
- Simple brute force cracking capabilities
- Dictionary attack functionality

## Features

- **Multiple Hash Algorithms**: Supports MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- **Hash Identification**: Automatically detect hash types based on length and format
- **Cracking Capabilities**: 
  - Brute force attacks (for weak/simple hashes)
  - Dictionary attacks using wordlists
- **Standard Hashing**: Calculate hashes for strings and files
- **Security-Focused**: Designed for authorized penetration testing activities

## Requirements

- Python 3.6+
- No external dependencies

## Installation

Simply clone or download the `enhanced_hash_tool.py` file.

## Usage

### Basic Hash Generation
```bash
# Hash a string with default SHA-256
python enhanced_hash_tool.py -s "password123"

# Hash a file
python enhanced_hash_tool.py -f /path/to/document.pdf

# Use specific algorithm
python enhanced_hash_tool.py -s "secret" -a sha1
```

### Hash Identification
```bash
# Identify what type of hash this might be
python enhanced_hash_tool.py --identify "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
```

### Hash Cracking

#### Brute Force Attack
```bash
# Attempt to crack a simple hash (effective only for very short inputs)
python enhanced_hash_tool.py --crack "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" --max-length 5
```

#### Dictionary Attack
```bash
# Use a wordlist to crack a hash
python enhanced_hash_tool.py --dict-crack "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" /path/to/wordlist.txt
```

## Important Security Notes

1. **Educational Purpose**: This tool is for learning and authorized security testing
2. **Limitations**: Real-world hash cracking requires specialized tools like John the Ripper or Hashcat
3. **Authorization**: Only use on systems you own or have explicit written permission to test
4. **Performance**: Built-in cracking methods are limited for demonstration purposes

## Legal Disclaimer

This tool is intended for authorized security testing only. Users must comply with all applicable laws and regulations. The creators are not responsible for misuse.

## Contributing

Feel free to fork and submit pull requests for improvements, additional features, or bug fixes.

## License

MIT License
