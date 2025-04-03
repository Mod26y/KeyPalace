#!/usr/bin/env python3
"""
Malware API Key Extractor

This script performs the following steps:
    1. Decrypts and extracts an AES‑encrypted ZIP file (password: "infected")
       to obtain a malware binary.
    2. Runs the 'strings' command on the extracted binary to extract printable strings.
    3. Filters the output for potential API keys/tokens using regex patterns.
    4. Saves the identified keys/tokens to a JSON file.

Usage:
    python malware_api_key_extractor.py
"""

import os
import sys
import json
import re
import logging
import subprocess
import pyzipper  # Requires installation: pip install pyzipper

def extract_zip(zip_file_path: str, extract_dir: str, password: str) -> list:
    """
    Extracts an AES‑encrypted ZIP file to a specified directory.

    Args:
        zip_file_path (str): Path to the encrypted ZIP file.
        extract_dir (str): Directory where the file(s) will be extracted.
        password (str): Password for decryption.

    Returns:
        list: A list of filenames extracted from the ZIP file.

    Raises:
        Exception: If extraction fails.
    """
    try:
        with pyzipper.AESZipFile(zip_file_path) as zf:
            zf.pwd = password.encode('utf-8')
            zf.extractall(path=extract_dir)
            extracted_files = zf.namelist()
            logging.info("Extraction successful: %s", extracted_files)
            return extracted_files
    except Exception as e:
        logging.error("Error extracting zip file: %s", e)
        raise

def run_strings(file_path: str) -> list:
    """
    Executes the 'strings' command on a given file and returns the output as a list of strings.

    Args:
        file_path (str): Path to the binary file.

    Returns:
        list: A list of printable strings extracted from the file.

    Raises:
        Exception: If the strings command fails.
    """
    try:
        result = subprocess.run(
            ["strings", file_path],
            capture_output=True,
            text=True,
            check=True
        )
        logging.info("Strings command executed successfully on %s", file_path)
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        logging.error("strings command failed: %s", e)
        raise

def filter_strings(strings_list: list) -> list:
    """
    Filters a list of strings for potential API keys or tokens using regex patterns.

    Args:
        strings_list (list): List of strings to search.

    Returns:
        list: A list of potential API keys/tokens found.
    """
    # Define regex patterns for common API key formats
    patterns = [
        r'api[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9\-_]{16,})["\']?',
        r'token\s*[:=]\s*["\']?([A-Za-z0-9\-_]{16,})["\']?',
        r'secret\s*[:=]\s*["\']?([A-Za-z0-9\-_]{16,})["\']?'
    ]
    regexes = [re.compile(p, re.IGNORECASE) for p in patterns]
    matches = set()

    for line in strings_list:
        for regex in regexes:
            found = regex.findall(line)
            if found:
                for match in found:
                    matches.add(match)

    logging.info("Filtering complete. %d potential keys found.", len(matches))
    return list(matches)

def save_results(results: list, output_file: str) -> None:
    """
    Saves the list of potential API keys/tokens to a JSON file.

    Args:
        results (list): List of keys/tokens.
        output_file (str): File path for the output JSON file.

    Raises:
        Exception: If saving the file fails.
    """
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        logging.info("Results saved to %s", output_file)
    except Exception as e:
        logging.error("Error saving results: %s", e)
        raise

def main():
    # Setup basic logging configuration
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )

    # Configuration
    zip_file_path = 'malware_sample.zip'
    extract_dir = 'extracted'
    password = 'infected'
    output_file = 'api_keys.json'

    # Ensure the extraction directory exists
    if not os.path.exists(extract_dir):
        os.makedirs(extract_dir)

    # Step 1: Extract the encrypted ZIP file
    try:
        extracted_files = extract_zip(zip_file_path, extract_dir, password)
    except Exception as e:
        logging.error("Extraction failed, terminating script")
        sys.exit(1)

    if not extracted_files:
        logging.error("No files were extracted. Terminating script.")
        sys.exit(1)

    # Assuming the first extracted file is the malware binary.
    malware_file_path = os.path.join(extract_dir, extracted_files[0])
    
    # Step 2: Run the strings command on the malware binary
    try:
        strings_output = run_strings(malware_file_path)
    except Exception as e:
        logging.error("Failed to run strings command, terminating script")
        sys.exit(1)

    # Step 3: Filter the strings output for potential API keys/tokens
    potential_keys = filter_strings(strings_output)

    # Step 4: Save the results to a JSON file
    try:
        save_results(potential_keys, output_file)
    except Exception as e:
        logging.error("Failed to save results, terminating script")
        sys.exit(1)

if __name__ == "__main__":
    main()
