# Usage Examples

## Hash Type Identification

### Identify Common Hash Formats
```bash
# Identify an MD5 hash
python enhanced_hash_tool.py --identify "5d41402abc4b2a76b9719d911017c592"

# Identify a SHA-256 hash
python enhanced_hash_tool.py --identify "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

# Unknown format detection
python enhanced_hash_tool.py --identify "abcdef1234567890"
```

Expected output:
```
Hash: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
Possible types: sha256
```

## Hash Cracking Examples

### Brute Force (Limited for Simple Cases)
```bash
# Crack a simple MD5 hash of a short lowercase word
python enhanced_hash_tool.py --crack "5d41402abc4b2a76b9719d911017c592" --max-length 6
```

### Dictionary Attack
```bash
# Create a simple wordlist for testing
echo -e "password\n123456\nadmin\nwelcome\ntest" > sample_wordlist.txt

# Crack using wordlist
python enhanced_hash_tool.py --dict-crack "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" sample_wordlist.txt
```

Expected success output:
```
SUCCESS: 'password' (md5)
```

## Standard Hashing Operations

### Generate Multiple Hash Types
```bash
# For strings
python enhanced_hash_tool.py -s "Hello World"

# For files
python enhanced_hash_tool.py -f document.pdf -a sha256
```

Note: The original main() function was cut off in the implementation. You may want to add the standard hashing code from previous examples or implement a complete main function that handles normal hashing along with the new features.
