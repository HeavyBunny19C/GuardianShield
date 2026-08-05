#!/usr/bin/env python3
"""
GuardianShield SHA-256 Hash Tool

Generates SHA-256 hashes for use in guardian_config.yaml:
  - admin.password_hash
  - admin.install_key is configured as plaintext and is not generated here

Usage:
  python hash_tool.py                  # Interactive mode (hidden input)
  python hash_tool.py --text "<text>"  # Direct text input
  python hash_tool.py --verify HASH    # Verify text against a known hash
"""

import argparse
import getpass
import hashlib
import sys


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def interactive_mode():
    print()
    print("=" * 50)
    print("  GuardianShield SHA-256 Hash Generator")
    print("=" * 50)
    print()
    print("Input will NOT be displayed on screen.")
    print()

    try:
        text = getpass.getpass("Enter text to hash: ")
        if not text:
            print("[ERROR] Empty input.")
            return 1
        confirm = getpass.getpass("Confirm (enter again): ")
        if text != confirm:
            print("[ERROR] Inputs do not match.")
            return 1
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        return 1

    digest = sha256_hex(text)
    print()
    print(f"SHA-256: {digest}")
    print()
    print("Paste this value into guardian_config.yaml:")
    print(f'  password_hash: "{digest}"')
    print()
    return 0


def direct_mode(text: str):
    digest = sha256_hex(text)
    print(digest)
    return 0


def verify_mode(expected_hash: str):
    try:
        text = getpass.getpass("Enter text to verify: ")
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        return 1

    digest = sha256_hex(text)
    if digest == expected_hash.lower().strip():
        print(f"[MATCH] Hash matches.")
        return 0
    else:
        print(f"[MISMATCH]")
        print(f"  Expected: {expected_hash.lower().strip()}")
        print(f"  Got:      {digest}")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="GuardianShield SHA-256 Hash Tool"
    )
    parser.add_argument(
        "--text", "-t",
        help="Text to hash (printed to stdout). Omit for interactive mode.",
    )
    parser.add_argument(
        "--verify", "-v",
        metavar="HASH",
        help="Verify input against an expected SHA-256 hash.",
    )
    args = parser.parse_args()

    if args.verify:
        return verify_mode(args.verify)
    elif args.text is not None:
        return direct_mode(args.text)
    else:
        return interactive_mode()


if __name__ == "__main__":
    sys.exit(main())
