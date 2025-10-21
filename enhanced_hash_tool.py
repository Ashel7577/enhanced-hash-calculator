#!/usr/bin/env python3
"""
Enhanced Hash Calculator with Lookup/Cracking Capabilities
"""

import hashlib
import argparse
import sys
import itertools
import string
import os

class EnhancedHashTool:
    def __init__(self):
        self.hash_algorithms = {
            32: ['md5'],      # MD5 produces 32-character hex
            40: ['sha1'],     # SHA-1 produces 40-character hex
            56: ['sha224'],   # SHA-224 produces 56-character hex
            64: ['sha256'],   # SHA-256 produces 64-character hex
            96: ['sha384'],   # SHA-384 produces 96-character hex
            128: ['sha512']   # SHA-512 produces 128-character hex
        }
        self.supported_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512
        }
    
    def identify_hash_type(self, hash_value):
        """Identify possible hash types based on length"""
        hash_len = len(hash_value)
        possible_types = self.hash_algorithms.get(hash_len, [])
        
        if not possible_types and hash_len % 2 == 0:
            # Check if it's hex
            try:
                int(hash_value, 16)
                return [f"Unknown ({hash_len}-char hexadecimal)"]
            except ValueError:
                pass
        
        return possible_types if possible_types else ["Unknown hash format"]
    
    def crack_simple_hash(self, target_hash, max_length=4, charset=string.ascii_lowercase + string.digits):
        """Simple brute force for demonstration purposes"""
        target_hash = target_hash.lower()
        hash_len = len(target_hash)
        
        # Identify algorithm based on hash length
        possible_algos = {
            32: hashlib.md5,
            40: hashlib.sha1,
            64: hashlib.sha256
        }
        
        hasher_class = possible_algos.get(hash_len)
        if not hasher_class:
            return None, f"Unsupported hash length: {hash_len}"
        
        print(f"Attempting brute force with {len(charset)} characters up to {max_length} chars...")
        
        # Try all combinations
        for length in range(1, min(max_length + 1, 6)):  # Limit for demo safety
            for guess in itertools.product(charset, repeat=length):
                guess_str = ''.join(guess)
                guess_hash = hasher_class(guess_str.encode()).hexdigest()
                
                if guess_hash == target_hash:
                    return guess_str, hasher_class.__name__
        
        return None, "Not found in brute force attempt"
    
    def dictionary_attack(self, target_hash, wordlist_path):
        """Attempt to crack hash using a wordlist"""
        target_hash = target_hash.lower()
        hash_len = len(target_hash)
        
        # Identify algorithm based on hash length
        possible_algos = {
            32: hashlib.md5,
            40: hashlib.sha1,
            64: hashlib.sha256
        }
        
        hasher_class = possible_algos.get(hash_len)
        if not hasher_class:
            return None, f"Unsupported hash length: {hash_len}"
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    word_hash = hasher_class(word.encode()).hexdigest()
                    
                    if word_hash == target_hash:
                        return word, hasher_class.__name__
                        
            return None, "Word not found in dictionary"
        except FileNotFoundError:
            return None, f"Wordlist file not found: {wordlist_path}"
    
    def calculate_string_hash(self, text, algorithm='sha256'):
        """Calculate hash of a string"""
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hasher = self.supported_algorithms[algorithm]()
        hasher.update(text.encode('utf-8'))
        return hasher.hexdigest()
    
    def calculate_file_hash(self, filepath, algorithm='sha256'):
        """Calculate hash of a file"""
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        hasher = self.supported_algorithms[algorithm]()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

def main():
    parser = argparse.ArgumentParser(description="Enhanced Hash Tool for Penetration Testing")
    parser.add_argument('-s', '--string', help='String to hash')
    parser.add_argument('-f', '--file', help='File to hash')
    parser.add_argument('-a', '--algorithm', default='sha256', 
                       choices=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'],
                       help='Hash algorithm to use')
    parser.add_argument('--identify', help='Identify hash type')
    parser.add_argument('--crack', help='Try to crack hash (brute force)')
    parser.add_argument('--dict-crack', nargs=2, metavar=('HASH', 'WORDLIST'),
                       help='Dictionary attack: hash wordlist_file')
    parser.add_argument('--max-length', type=int, default=4,
                       help='Max length for brute force (default: 4)')
    
    args = parser.parse_args()
    
    tool = EnhancedHashTool()
    
    # Hash identification
    if args.identify:
        hash_types = tool.identify_hash_type(args.identify)
        print(f"Hash: {args.identify}")
        print(f"Possible types: {', '.join(hash_types)}")
        return
    
    # Hash cracking - brute force
    if args.crack:
        result, method = tool.crack_simple_hash(args.crack, args.max_length)
        if result:
            print(f"SUCCESS: '{result}' ({method})")
        else:
            print(f"FAILED: {method}")
        return
    
    # Hash cracking - dictionary
    if args.dict_crack:
        target_hash, wordlist = args.dict_crack
        result, method = tool.dictionary_attack(target_hash, wordlist)
        if result:
            print(f"SUCCESS: '{result}' ({method})")
        else:
            print(f"FAILED: {method}")
        return
    
    # Regular hashing
    if not args.string and not args.file:
        print("Error: Please specify either a string (-s) or file (-f) to hash")
        parser.print_help()
        sys.exit(1)
    
    if args.string and args.file:
        print("Error: Please specify either a string or file, not both")
        sys.exit(1)
    
    # Standard hashing
    try:
        if args.string:
            result = tool.calculate_string_hash(args.string, args.algorithm)
            print(f"String: {args.string}")
            print(f"{args.algorithm.upper()}: {result}")
        elif args.file:
            result = tool.calculate_file_hash(args.file, args.algorithm)
            print(f"File: {args.file}")
            print(f"{args.algorithm.upper()}: {result}")
    except Exception as e:
        print(f"Error during hashing: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
