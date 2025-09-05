#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GhostTech Password Checker
A CLI tool for assessing password strength and checking breach status.

Author: GhostTech Enterprise LLC
"""

import argparse
import getpass
import hashlib
import math
import re
import sys
from collections import Counter
from typing import Dict, List, Tuple, Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = RESET = ""
    class Back:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""


class PasswordStrengthChecker:
    """Main class for password strength assessment and breach checking."""
    
    def __init__(self):
        self.common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123', 
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            '1234567890', 'iloveyou', 'princess', 'rockyou', 'baseball',
            'dragon', 'football', 'sunshine', 'superman', 'trustno1'
        }
        
        self.common_patterns = [
            r'(.)\1{2,}',  # Repeated characters (aaa, 111)
            r'(012|123|234|345|456|567|678|789)',  # Sequential numbers
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
            r'(qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)',  # Keyboard patterns
        ]

    def calculate_entropy(self, password: str) -> float:
        """Calculate Shannon entropy of password."""
        if not password:
            return 0.0
        
        char_counts = Counter(password)
        password_length = len(password)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / password_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy

    def get_character_pool_size(self, password: str) -> int:
        """Determine the character pool size based on password composition."""
        pool_size = 0
        
        if re.search(r'[a-z]', password):
            pool_size += 26
        if re.search(r'[A-Z]', password):
            pool_size += 26
        if re.search(r'[0-9]', password):
            pool_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?`~]', password):
            pool_size += 32
        
        return pool_size

    def check_common_patterns(self, password: str) -> List[str]:
        """Check for common password patterns."""
        found_patterns = []
        password_lower = password.lower()
        
        for pattern in self.common_patterns:
            if re.search(pattern, password_lower):
                found_patterns.append("Contains common keyboard/sequential patterns")
                break
        
        if password_lower in self.common_passwords:
            found_patterns.append("Password is in common passwords list")
        
        if len(set(password)) < len(password) * 0.3:
            found_patterns.append("Too many repeated characters")
        
        return found_patterns

    def assess_strength(self, password: str) -> Dict:
        """Comprehensive password strength assessment."""
        if not password:
            return {
                'score': 0,
                'strength': 'VERY_WEAK',
                'issues': ['Password is empty'],
                'suggestions': ['Enter a password'],
                'entropy': 0.0,
                'estimated_crack_time': 'Instant'
            }
        
        score = 0
        issues = []
        suggestions = []
        
        # Length check
        length = len(password)
        if length < 8:
            issues.append("Too short (minimum 8 characters recommended)")
            suggestions.append("Use at least 8 characters")
        elif length < 12:
            score += 10
            suggestions.append("Consider using 12+ characters for better security")
        elif length < 16:
            score += 20
        else:
            score += 25
        
        # Character diversity
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?`~]', password))
        
        char_types = sum([has_lower, has_upper, has_digit, has_symbol])
        
        if char_types == 1:
            issues.append("Only uses one character type")
            suggestions.append("Mix uppercase, lowercase, numbers, and symbols")
        elif char_types == 2:
            score += 10
            suggestions.append("Add numbers and symbols for better security")
        elif char_types == 3:
            score += 20
            suggestions.append("Add symbols for maximum security")
        else:
            score += 30
        
        # Entropy calculation
        entropy = self.calculate_entropy(password)
        pool_size = self.get_character_pool_size(password)
        
        if entropy < 2.5:
            issues.append("Very low entropy (predictable)")
        elif entropy < 3.5:
            score += 5
        else:
            score += 15
        
        # Check for common patterns
        pattern_issues = self.check_common_patterns(password)
        issues.extend(pattern_issues)
        
        if pattern_issues:
            suggestions.append("Avoid common patterns and dictionary words")
        
        # Calculate estimated crack time
        if pool_size > 0 and length > 0:
            possible_combinations = pool_size ** length
            # Assume 1 billion guesses per second for modern hardware
            seconds_to_crack = possible_combinations / (2 * 1_000_000_000)
            crack_time = self.format_time(seconds_to_crack)
        else:
            crack_time = "Unknown"
        
        # Determine overall strength
        if score < 20:
            strength = 'VERY_WEAK'
        elif score < 40:
            strength = 'WEAK'
        elif score < 60:
            strength = 'FAIR'
        elif score < 80:
            strength = 'STRONG'
        else:
            strength = 'VERY_STRONG'
        
        return {
            'score': score,
            'strength': strength,
            'issues': issues,
            'suggestions': suggestions,
            'entropy': entropy,
            'estimated_crack_time': crack_time,
            'character_types': char_types,
            'length': length
        }

    def format_time(self, seconds: float) -> str:
        """Format time duration in human-readable format."""
        if seconds < 1:
            return "Less than 1 second"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        elif seconds < 31536000000:
            return f"{seconds/31536000:.1f} years"
        else:
            return "Millions of years"

    def check_hibp(self, password: str) -> Tuple[bool, Optional[int]]:
        """Check if password appears in Have I Been Pwned database using k-anonymity."""
        if not REQUESTS_AVAILABLE:
            return False, None
        
        # Create SHA-1 hash of password
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        try:
            # Query HIBP API with first 5 characters of hash
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # Check if our hash suffix appears in the response
            for line in response.text.splitlines():
                hash_suffix, count = line.split(':')
                if hash_suffix == suffix:
                    return True, int(count)
            
            return False, 0
        
        except requests.RequestException:
            # Return None to indicate we couldn't check
            return False, None


def print_colored(text: str, color: str = "", style: str = "") -> None:
    """Print colored text if colorama is available."""
    if COLORAMA_AVAILABLE:
        color_code = getattr(Fore, color.upper(), "")
        style_code = getattr(Style, style.upper(), "")
        print(f"{color_code}{style_code}{text}{Style.RESET_ALL}")
    else:
        print(text)


def print_strength_report(assessment: Dict, pwned_info: Tuple[bool, Optional[int]] = None) -> None:
    """Print a detailed strength assessment report."""
    print("\n" + "="*50)
    print_colored("GHOSTTECH PASSWORD ANALYSIS REPORT", "cyan", "bright")
    print("="*50)
    
    # Strength assessment
    strength = assessment['strength']
    score = assessment['score']
    
    strength_colors = {
        'VERY_WEAK': 'red',
        'WEAK': 'red', 
        'FAIR': 'yellow',
        'STRONG': 'green',
        'VERY_STRONG': 'green'
    }
    
    color = strength_colors.get(strength, 'white')
    print_colored(f"\nOverall Strength: {strength} ({score}/100)", color, "bright")
    
    # Technical details
    print(f"\nTechnical Analysis:")
    print(f"   • Length: {assessment['length']} characters")
    print(f"   • Character Types: {assessment['character_types']}/4")
    print(f"   • Entropy: {assessment['entropy']:.2f} bits")
    print(f"   • Estimated Crack Time: {assessment['estimated_crack_time']}")
    
    # Issues
    if assessment['issues']:
        print_colored(f"\nIssues Found:", "red", "bright")
        for issue in assessment['issues']:
            print_colored(f"   • {issue}", "red")
    
    # Suggestions
    if assessment['suggestions']:
        print_colored(f"\nSuggestions:", "yellow", "bright")
        for suggestion in assessment['suggestions']:
            print_colored(f"   • {suggestion}", "yellow")
    
    # Breach check results
    if pwned_info is not None:
        is_pwned, count = pwned_info
        if is_pwned and count is not None:
            print_colored(f"\nBREACH ALERT: Password found {count:,} times in data breaches!", "red", "bright")
            print_colored("   RECOMMENDATION: Change this password immediately!", "red")
        elif count == 0:
            print_colored(f"\nGood news: Password not found in known breaches", "green")
        else:
            print_colored(f"\nCould not check breach database (network error)", "yellow")
    
    print("\n" + "="*50)


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description="GhostTech Password Checker - Assess password strength and check breaches",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Interactive mode (recommended)
  %(prog)s -p "mypassword"         # Check specific password
  %(prog)s --no-breach             # Skip breach checking
  %(prog)s -v                      # Verbose output
        """
    )
    
    parser.add_argument('-p', '--password', 
                       help='Password to check (not recommended for security)')
    parser.add_argument('--no-breach', action='store_true',
                       help='Skip Have I Been Pwned breach checking')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    print_colored("GhostTech Password Checker", "cyan", "bright")
    print_colored("   Secure password strength assessment", "cyan")
    print()
    
    if not REQUESTS_AVAILABLE and not args.no_breach:
        print_colored("Warning: 'requests' library not found. Install with: pip install requests", "yellow")
        print_colored("   Breach checking will be skipped.", "yellow")
        print()
    
    # Get password
    if args.password:
        password = args.password
        if args.verbose:
            print_colored("Warning: Password provided via command line (less secure)", "yellow")
    else:
        try:
            password = getpass.getpass("Enter password to analyze (hidden): ")
        except KeyboardInterrupt:
            print_colored("\n\nOperation cancelled.", "yellow")
            sys.exit(0)
    
    if not password:
        print_colored("Error: No password provided.", "red")
        sys.exit(1)
    
    # Initialize checker and assess password
    checker = PasswordStrengthChecker()
    assessment = checker.assess_strength(password)
    
    # Check breaches if enabled
    pwned_info = None
    if not args.no_breach and REQUESTS_AVAILABLE:
        if args.verbose:
            print("Checking Have I Been Pwned database...")
        try:
            pwned_info = checker.check_hibp(password)
        except Exception as e:
            if args.verbose:
                print_colored(f"Breach check failed: {e}", "yellow")
    
    # Print results
    print_strength_report(assessment, pwned_info)
    
    # Exit with appropriate code
    if assessment['strength'] in ['VERY_WEAK', 'WEAK']:
        sys.exit(1)
    elif pwned_info and pwned_info[0] and pwned_info[1] and pwned_info[1] > 0:
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
