import base64
import re
import sys
import argparse
from pathlib import Path

# --- Validation Functions ---
def is_hex(s: str) -> bool:
    """Validate hexadecimal format"""
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def check_cisco_type7(s: str) -> bool:
    """Validate Cisco Type 7 password encryption"""
    if len(s) < 2:
        return False
    salt_index = s[:2]
    if not salt_index.isdigit() or not 0 <= int(salt_index) <= 15:
        return False
    return len(s[2:]) % 2 == 0 and is_hex(s[2:])

def check_openssl_salted(s: str) -> bool:
    """Validate OpenSSL salted encryption format"""
    try:
        decoded = base64.b64decode(s)
        return decoded.startswith(b'Salted__') and len(decoded) > 16
    except:
        return False

def analyze_character_distribution(s: str) -> dict:
    """Analyze character distribution patterns"""
    char_count = {}
    for c in s:
        char_count[c] = char_count.get(c, 0) + 1
    return {
        'unique_chars': len(char_count),
        'digit_ratio': sum(1 for c in s if c.isdigit()) / len(s),
        'upper_ratio': sum(1 for c in s if c.isupper()) / len(s),
        'lower_ratio': sum(1 for c in s if c.islower()) / len(s),
        'special_ratio': sum(1 for c in s if not c.isalnum()) / len(s)
    }

def check_entropy(s: str) -> float:
    """Calculate Shannon entropy of the string"""
    import math
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    entropy = - sum(p * math.log(p) / math.log(2.0) for p in prob)
    return entropy

# --- Constants and Precompiled Patterns ---
HASH_REGEX = re.compile(r'^[\w\d\-_$./@!*+=]+$')  # More permissive regex for initial validation
BASE64_REGEX = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')

# Enhanced hash characteristics
HASH_TYPES = {
    # 1. Forensics (Integrity & Evidence Verification)
    'MD5': {
        'length': 32,
        'hex': True,
        'characteristics': {
            'min_entropy': 3.5,
            'unique_chars_min': 10,
            'digit_ratio_range': (0.2, 0.6),
        }
    },
    'SHA-1': {
        'length': 40,
        'hex': True,
        'characteristics': {
            'min_entropy': 3.7,
            'unique_chars_min': 12,
            'digit_ratio_range': (0.2, 0.6),
        }
    },
    'SHA-224': {
        'length': 56,
        'hex': True,
        'characteristics': {
            'min_entropy': 3.8,
            'unique_chars_min': 14,
            'digit_ratio_range': (0.2, 0.6),
        }
    },
    'SHA-256': {
        'length': 64,
        'hex': True,
        'characteristics': {
            'min_entropy': 3.9,
            'unique_chars_min': 15,
            'digit_ratio_range': (0.2, 0.6),
        }
    },
    'SHA-384': {
        'length': 96,
        'hex': True,
        'characteristics': {
            'min_entropy': 4.0,
            'unique_chars_min': 20,
            'digit_ratio_range': (0.2, 0.6),
        }
    },
    'SHA-512': {
        'length': 128,
        'hex': True,
        'characteristics': {
            'min_entropy': 4.1,
            'unique_chars_min': 25,
            'digit_ratio_range': (0.2, 0.6),
        }
    },
    'CRC32': {
        'length': 8,
        'hex': True,
        'characteristics': {
            'min_entropy': 2.5,
            'unique_chars_min': 6,
        }
    },
    'xxHash': {
        'length': 16,
        'hex': True,
        'characteristics': {
            'min_entropy': 3.0,
            'unique_chars_min': 8,
        }
    },
    
    # 2. Web Security (Password Storage & Authentication)
    'bcrypt': {
        'pattern': re.compile(r'^\$2[abxy]\$\d{2}\$[A-Za-z0-9./]{53}$'),
        'characteristics': {
            'starts_with': '$2',
            'special_chars': ['$', '.', '/'],
        }
    },
    'PBKDF2': {
        'pattern': re.compile(r'^\$pbkdf2(-sha\d+)?\$\d+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+$'),
        'characteristics': {
            'starts_with': '$pbkdf2',
            'contains': ['$'],
        }
    },
    'scrypt': {
        'pattern': re.compile(r'^\$scrypt\$[A-Za-z0-9./]+$'),
        'characteristics': {
            'starts_with': '$scrypt',
            'special_chars': ['$', '.'],
        }
    },
    'Argon2': {
        'pattern': re.compile(r'^\$argon2[id][v=\d]+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+'),
        'characteristics': {
            'starts_with': '$argon2',
            'contains': ['m=', 't=', 'p='],
        }
    },
    'HMAC': {
        'pattern': re.compile(r'^[A-Fa-f0-9]{32,128}$'),
        'characteristics': {
            'min_entropy': 3.8,
            'hex': True,
        }
    },
    
    # 3. Cryptography (Data Integrity & Digital Signatures)
    'SHA-3-224': {
        'length': 56,
        'hex': True,
        'characteristics': {
            'min_entropy': 3.8,
            'unique_chars_min': 14,
        }
    },
    'SHA-3-256': {
        'length': 64,
        'hex': True,
        'characteristics': {
            'min_entropy': 3.9,
            'unique_chars_min': 15,
        }
    },
    'SHA-3-384': {
        'length': 96,
        'hex': True,
        'characteristics': {
            'min_entropy': 4.0,
            'unique_chars_min': 20,
        }
    },
    'SHA-3-512': {
        'length': 128,
        'hex': True,
        'characteristics': {
            'min_entropy': 4.1,
            'unique_chars_min': 25,
        }
    },
    'Blake2b': {
        'pattern': re.compile(r'^[A-Fa-f0-9]{128}$'),
        'characteristics': {
            'min_entropy': 4.1,
            'unique_chars_min': 25,
        }
    },
    'Blake2s': {
        'pattern': re.compile(r'^[A-Fa-f0-9]{64}$'),
        'characteristics': {
            'min_entropy': 3.9,
            'unique_chars_min': 15,
        }
    },
    'Blake3': {
        'pattern': re.compile(r'^[A-Fa-f0-9]{64}$'),
        'characteristics': {
            'min_entropy': 3.9,
            'unique_chars_min': 15,
        }
    },
    'Whirlpool': {
        'length': 128,
        'hex': True,
        'characteristics': {
            'min_entropy': 4.1,
            'unique_chars_min': 25,
        }
    },
    'RIPEMD-160': {
        'length': 40,
        'hex': True,
        'characteristics': {
            'min_entropy': 3.7,
            'unique_chars_min': 12,
        }
    },
    'Tiger-192': {
        'length': 48,
        'hex': True,
        'characteristics': {
            'min_entropy': 3.8,
            'unique_chars_min': 13,
        }
    },
    
    # 4. Reverse Engineering (Malware Analysis & Binary Verification)
    'Imphash': {
        'pattern': re.compile(r'^[a-f0-9]{32}$'),
        'characteristics': {
            'min_entropy': 3.5,
            'all_lower': True,
        }
    },
    'ssdeep': {
        'pattern': re.compile(r'^\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+$'),
        'characteristics': {
            'contains': [':'],
            'special_chars': [':', '/', '+'],
        }
    },
    'TLSH': {
        'pattern': re.compile(r'^T1[A-Fa-f0-9]{68}$'),
        'characteristics': {
            'starts_with': 'T1',
            'length': 70,
        }
    },
    'MurmurHash': {
        'pattern': re.compile(r'^[A-Fa-f0-9]{8}$'),
        'characteristics': {
            'min_entropy': 3.0,
            'unique_chars_min': 6,
        }
    },
    
    # 5. Other Notable Hashing Algorithms
    'CityHash': {
        'pattern': re.compile(r'^[A-Fa-f0-9]{16}$'),
        'characteristics': {
            'min_entropy': 3.2,
            'unique_chars_min': 8,
        }
    },
    'FarmHash': {
        'pattern': re.compile(r'^[A-Fa-f0-9]{16}$'),
        'characteristics': {
            'min_entropy': 3.2,
            'unique_chars_min': 8,
        }
    },
    'SipHash': {
        'pattern': re.compile(r'^[A-Fa-f0-9]{16}$'),
        'characteristics': {
            'min_entropy': 3.2,
            'unique_chars_min': 8,
        }
    },
    'Adler-32': {
        'length': 8,
        'hex': True,
        'characteristics': {
            'min_entropy': 2.5,
            'unique_chars_min': 6,
        }
    },
    'FNV-1a': {
        'pattern': re.compile(r'^[A-Fa-f0-9]{8,16}$'),
        'characteristics': {
            'min_entropy': 3.0,
            'unique_chars_min': 7,
        }
    },
    'DJB2': {
        'pattern': re.compile(r'^[A-Fa-f0-9]{8}$'),
        'characteristics': {
            'min_entropy': 3.0,
            'unique_chars_min': 6,
        }
    },
    
    # Additional formats from previous implementation...
    'Windows Domain Cached Credentials': {
        'pattern': re.compile(r'^[a-f0-9]{32}:[a-f0-9]{32}$')
    },
    'MySQL 4.1+': {
        'length': (40, 41),
        'validator': lambda s: (s[0] == '*' or len(s) == 40) and is_hex(s.lstrip('*')),
        'characteristics': {
            'starts_with': '*',
        }
    },
    'PostgreSQL MD5': {
        'pattern': re.compile(r'^md5[a-f0-9]{32}$')
    },
    'Oracle H': {
        'pattern': re.compile(r'^[A-F0-9]{32}$')
    },
    'Cisco Type 7': {
        'validator': check_cisco_type7
    },
    'Cisco Type 8': {
        'pattern': re.compile(r'^\$8\$[a-zA-Z0-9./]{14}\$[a-zA-Z0-9./]{43}$')
    },
    'Cisco Type 9': {
        'pattern': re.compile(r'^\$9\$[a-zA-Z0-9./]{14}\$[a-zA-Z0-9./]{43}$')
    },
}

def calculate_hash_score(input_str: str, hash_type: str, config: dict) -> float:
    """Calculate how well the input matches the hash type characteristics"""
    score = 0.0
    char_stats = analyze_character_distribution(input_str)
    entropy = check_entropy(input_str)
    
    # Basic checks
    if 'length' in config:
        if isinstance(config['length'], tuple):
            if len(input_str) in range(config['length'][0], config['length'][1] + 1):
                score += 1.0
        elif len(input_str) == config['length']:
            score += 1.0
    
    if config.get('hex', False) and is_hex(input_str):
        score += 1.0
    
    # Pattern matching
    if 'pattern' in config and config['pattern'].match(input_str):
        score += 2.0
    
    # Custom validator
    if 'validator' in config and config['validator'](input_str):
        score += 1.0
    
    # Characteristics checks
    if 'characteristics' in config:
        chars = config['characteristics']
        
        if 'min_entropy' in chars and entropy >= chars['min_entropy']:
            score += 0.5
        
        if 'unique_chars_min' in chars and char_stats['unique_chars'] >= chars['unique_chars_min']:
            score += 0.5
            
        if 'digit_ratio_range' in chars:
            min_ratio, max_ratio = chars['digit_ratio_range']
            if min_ratio <= char_stats['digit_ratio'] <= max_ratio:
                score += 0.5
                
        if 'all_upper' in chars and chars['all_upper']:
            if char_stats['upper_ratio'] == 1.0:
                score += 0.5
                
        if 'starts_with' in chars and input_str.startswith(chars['starts_with']):
            score += 1.0
            
        if 'contains' in chars:
            if all(pattern in input_str for pattern in chars['contains']):
                score += 1.0
    
    return score

def detect_hash_type(input_str: str, verbose: bool = False) -> list:
    """Advanced detection with improved scoring system for more accurate results"""
    matches = []
    scores = {}
    input_str = input_str.strip()
    
    if not input_str:
        return matches

    # Calculate scores for each hash type
    for name, config in HASH_TYPES.items():
        try:
            score = calculate_hash_score(input_str, name, config)
            if score > 2.0:  # Increased minimum threshold
                scores[name] = score
                if verbose:
                    print(f"[*] {name} score: {score:.2f}")
        except Exception as e:
            if verbose:
                print(f"[!] Error checking {name}: {str(e)}")
    
    # Filter and sort results
    if scores:
        max_score = max(scores.values())
        
        # Adjust threshold based on max score
        if max_score >= 4.0:
            threshold = max_score * 0.9  # More strict for high-confidence matches
        else:
            threshold = max_score * 0.85  # Slightly more lenient for medium-confidence matches
        
        # Sort by score in descending order and filter
        matches = [name for name, score in sorted(scores.items(), key=lambda x: x[1], reverse=True)
                  if score >= threshold]
        
        # Limit to top 3 matches if they're very close in score
        if len(matches) > 3:
            top_score = scores[matches[0]]
            matches = [m for m in matches[:3] if scores[m] >= top_score * 0.95]
    
    return matches

# --- Documentation Links ---
DOC_LINKS = {
    # Forensics
    'MD5': 'https://en.wikipedia.org/wiki/MD5',
    'SHA-1': 'https://en.wikipedia.org/wiki/SHA-1',
    'SHA-256': 'https://en.wikipedia.org/wiki/SHA-2',
    'SHA-512': 'https://en.wikipedia.org/wiki/SHA-2',
    'CRC32': 'https://en.wikipedia.org/wiki/Cyclic_redundancy_check',
    'xxHash': 'https://github.com/Cyan4973/xxHash',
    
    # Web Security
    'bcrypt': 'https://en.wikipedia.org/wiki/Bcrypt',
    'PBKDF2': 'https://en.wikipedia.org/wiki/PBKDF2',
    'scrypt': 'https://en.wikipedia.org/wiki/Scrypt',
    'Argon2': 'https://en.wikipedia.org/wiki/Argon2',
    'HMAC': 'https://en.wikipedia.org/wiki/HMAC',
    
    # Cryptography
    'SHA-3-256': 'https://en.wikipedia.org/wiki/SHA-3',
    'Blake2': 'https://www.blake2.net/',
    'Blake3': 'https://github.com/BLAKE3-team/BLAKE3',
    'Whirlpool': 'https://en.wikipedia.org/wiki/Whirlpool_(hash_function)',
    'RIPEMD-160': 'https://en.wikipedia.org/wiki/RIPEMD',
    'Tiger': 'https://en.wikipedia.org/wiki/Tiger_(hash_function)',
    
    # Reverse Engineering
    'Imphash': 'https://www.mandiant.com/resources/blog/tracking-malware-import-hashing',
    'ssdeep': 'https://ssdeep-project.github.io/ssdeep/',
    'TLSH': 'https://github.com/trendmicro/tlsh',
    'MurmurHash': 'https://en.wikipedia.org/wiki/MurmurHash',
    
    # Other
    'CityHash': 'https://github.com/google/cityhash',
    'FarmHash': 'https://github.com/google/farmhash',
    'SipHash': 'https://en.wikipedia.org/wiki/SipHash',
    'Adler-32': 'https://en.wikipedia.org/wiki/Adler-32',
    'FNV-1a': 'https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function',
    
    # Previously existing links
    'JWT Token': 'https://jwt.io/introduction',
}

# --- UI/UX Components ---
def format_results(results, verbose: bool) -> str:
    """Generate formatted output with improved confidence levels and categorization"""
    output = []
    
    if isinstance(results, dict):
        # Handle multiple hashes from file
        output.append("\nRESULTS:")
        for hash_str, hash_types in results.items():
            output.append(f"\nHash: {hash_str}")
            if hash_types:
                output.append("Most Likely Hash Types:")
                for i, hash_type in enumerate(hash_types, 1):
                    if i == 1:
                        confidence = "Very High" if len(hash_types) == 1 else "High"
                    elif i == 2:
                        confidence = "Medium"
                    else:
                        confidence = "Low"
                    output.append(f"  {i}. {hash_type} (Confidence: {confidence})")
                    if verbose and hash_type in DOC_LINKS:
                        output.append(f"     Documentation: {DOC_LINKS[hash_type]}")
            else:
                output.append("  No recognized hash types found")
    else:
        # Handle single hash
        if results:
            output.append("\nMOST LIKELY HASH TYPES:")
            for i, res in enumerate(results, 1):
                if i == 1:
                    confidence = "Very High" if len(results) == 1 else "High"
                elif i == 2:
                    confidence = "Medium"
                else:
                    confidence = "Low"
                output.append(f"  {i}. {res} (Confidence: {confidence})")
                if verbose and res in DOC_LINKS:
                    output.append(f"     Documentation: {DOC_LINKS[res]}")
        else:
            output.append("\nNo recognized hash types found")
    
    return "\n".join(output)

def print_banner():
    """Display tool banner and attribution"""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                         HashWizard v1.0                           ║
║                                                                   ║
║           Advanced Hash Type Detection & Analysis Tool            ║
║                    Created by Reo-0x                              ║
╚═══════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def print_help():
    """Display detailed help information"""
    help_text = """
HashWizard - Advanced Hash Type Detection Tool
Created by Reo-0x

Usage:
    python HashWizard.py [options] [hash_string]
    python HashWizard.py -f <file_path>

Options:
    -h, --help      Show this help message
    -v, --verbose   Enable verbose output with additional details
    -f, --file      Process multiple hashes from a file (one per line)

Examples:
    python HashWizard.py 5f4dcc3b5aa765d61d8327deb882cf99
    python HashWizard.py -v '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBO.BtXHJMgKlO'
    python HashWizard.py -f hashes.txt

Supported Hash Types:
    • Basic Hashes (MD5, SHA-1, SHA-256, etc.)
    • Password Hashes (bcrypt, Argon2, PBKDF2)
    • Windows Hashes (LM, NTLM)
    • Database Hashes (MySQL, PostgreSQL)
    • And many more...
"""
    print(help_text)

# --- Main Application Flow ---
def main():
    """Enhanced command-line interface controller"""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('input', nargs='?', default=None)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-f', '--file', type=str)
    parser.add_argument('-h', '--help', action='store_true')
    
    args = parser.parse_args()
    
    # Show banner unless help is requested
    if not args.help:
        print_banner()

    if args.help:
        print_help()
        return

    try:
        if args.file:
            file_path = Path(args.file)
            if not file_path.exists():
                raise FileNotFoundError(f"Input file not found: {args.file}")
            if not file_path.is_file():
                raise ValueError(f"Not a regular file: {args.file}")
                
            with open(file_path, 'r', encoding='utf-8') as f:
                hashes = [line.strip() for line in f if line.strip()]
                
            if not hashes:
                print("\nNo valid hashes found in the file")
                return
                
            results = {}
            for h in hashes:
                if HASH_REGEX.match(h):
                    results[h] = detect_hash_type(h, args.verbose)
                else:
                    results[h] = []
                    if args.verbose:
                        print(f"[!] Skipping invalid input: {h}")
                
            print(format_results(results, args.verbose))
            return
            
        input_str = args.input or input("Enter hash/encrypted string: ").strip()
        
        if not input_str:
            print("\nError: Empty input")
            return
            
        if not HASH_REGEX.match(input_str):
            print("\nWarning: Input contains unexpected characters, but attempting detection anyway...")
            
        results = detect_hash_type(input_str, args.verbose)
        print(format_results(results, args.verbose))
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] {str(e)}")
        print("Use --help for usage information")
        sys.exit(1)

if __name__ == "__main__":
    main()