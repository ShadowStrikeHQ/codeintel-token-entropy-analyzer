import argparse
import math
import os
import logging
import sys
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Calculate the entropy of tokens in files.")
    parser.add_argument("filepath", help="Path to the file to analyze.")
    parser.add_argument(
        "--min_length",
        type=int,
        default=8,
        help="Minimum length of tokens to consider (default: 8).",
    )
    parser.add_argument(
        "--regex",
        type=str,
        default=r"[A-Za-z0-9_\-]+",
        help="Regex to define tokens (default: [A-Za-z0-9_\-]+).  Be careful with special regex characters.",
    )
    parser.add_argument(
        "--entropy_threshold",
        type=float,
        default=3.0,  # Example threshold
        help="Entropy threshold to flag tokens (default: 3.0).",
    )
    return parser.parse_args()

def calculate_entropy(token):
    """
    Calculates the Shannon entropy of a given token.

    Args:
        token (str): The token for which to calculate entropy.

    Returns:
        float: The Shannon entropy of the token.
    """
    if not token:
        return 0.0

    probability = [float(token.count(c)) / len(token) for c in dict.fromkeys(list(token))]
    entropy = -sum([p * math.log(p, 2.0) for p in probability])
    return entropy

def analyze_file(filepath, min_length, regex, entropy_threshold):
    """
    Analyzes a file for tokens and calculates their entropy.

    Args:
        filepath (str): The path to the file to analyze.
        min_length (int): The minimum length of tokens to consider.
        regex (str): The regular expression to identify tokens.
        entropy_threshold (float): The entropy threshold to flag tokens.

    Returns:
        None
    """
    try:
        with open(filepath, 'r') as f:
            content = f.read()

        # Find all tokens that match the regex
        tokens = re.findall(regex, content)

        for token in tokens:
            if len(token) >= min_length:
                entropy = calculate_entropy(token)
                logging.debug(f"Token: {token}, Entropy: {entropy}")
                if entropy >= entropy_threshold:
                    print(f"Potential secret found in {filepath}: Token: {token}, Entropy: {entropy}")
                elif entropy > 0:
                    logging.info(f"Token found in {filepath}: Token: {token}, Entropy: {entropy}")
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        sys.exit(1)
    except IOError as e:
        logging.error(f"Error reading file: {filepath} - {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

def main():
    """
    Main function to execute the token entropy analysis.
    """
    args = setup_argparse()

    # Input validation: Check if the filepath exists
    if not os.path.exists(args.filepath):
        logging.error(f"The file path '{args.filepath}' does not exist.")
        sys.exit(1)

    # Input validation: Check if min_length is a positive integer
    if args.min_length <= 0:
        logging.error("Minimum length must be a positive integer.")
        sys.exit(1)

    # Input validation: Check if entropy_threshold is non-negative
    if args.entropy_threshold < 0:
        logging.error("Entropy threshold must be non-negative.")
        sys.exit(1)

    # Security:  Consider more advanced escaping or sanitization if args.regex
    # will be used in a security-sensitive context.  Using it directly in re.findall
    # should be OK, but review if user input is used elsewhere.

    logging.info(f"Analyzing file: {args.filepath}")
    analyze_file(args.filepath, args.min_length, args.regex, args.entropy_threshold)
    logging.info("Analysis complete.")

if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Analyze a file with default settings:
#    python main.py example.txt
#
# 2. Analyze a file with a minimum token length of 12:
#    python main.py example.txt --min_length 12
#
# 3. Analyze a file with a custom regex:
#    python main.py example.txt --regex "[0-9a-f]{32}"  # Example: MD5 hash
#
# 4. Analyze a file with a different entropy threshold:
#    python main.py example.txt --entropy_threshold 4.0
#
# Offensive Tool Considerations:
# - Integrate with other security tools for automated vulnerability scanning.
# - Expand regex to include common API key patterns and secret formats.
# - Implement rules to ignore known false positives (e.g., common variable names).
# - Add support for analyzing entire directory structures.
# - Consider adding options to redact or obfuscate identified secrets in output for security.