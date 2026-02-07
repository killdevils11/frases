#!/usr/bin/env python3
"""
BIP-39 Offline Tool (English wordlist)

Features:
- Generate valid 12- or 24-word BIP-39 mnemonics (with checksum)
- Generate multiple phrases
- Auto-save to a .txt file (one phrase per line)
- Validate a mnemonic (words + checksum)

SECURITY NOTES:
- Run offline (disconnect internet) if you're going to use this for anything serious.
- Never share your mnemonic/seed phrase with anyone.
- For real funds, prefer generating inside a trusted wallet (e.g., MetaMask / hardware wallet).
"""

from __future__ import annotations
import secrets
import hashlib
from pathlib import Path

WORDLIST_FILENAME = "english.txt"


def load_wordlist(path: str | Path = WORDLIST_FILENAME) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Wordlist not found: {p}\n"
            f"Put '{WORDLIST_FILENAME}' in the same folder as this script, or edit WORDLIST_FILENAME."
        )
    words = [w.strip() for w in p.read_text(encoding="utf-8").splitlines() if w.strip()]
    if len(words) != 2048:
        raise ValueError(f"Wordlist must have 2048 words, found {len(words)}")
    return words


def _bytes_to_bits(b: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in b)


def _bits_to_int(bits: str) -> int:
    return int(bits, 2)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def generate_mnemonic(num_words: int, wordlist: list[str]) -> str:
    """
    Generate a VALID BIP-39 mnemonic with checksum.
    Allowed num_words: 12, 15, 18, 21, 24
    """
    if num_words not in (12, 15, 18, 21, 24):
        raise ValueError("num_words must be one of: 12, 15, 18, 21, 24")

    # Entropy length in bits: 128..256 step 32
    entropy_bits = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}[num_words]
    entropy = secrets.token_bytes(entropy_bits // 8)

    # Checksum length = ENT/32
    cs_len = entropy_bits // 32
    hash_bits = _bytes_to_bits(_sha256(entropy))
    checksum = hash_bits[:cs_len]

    bits = _bytes_to_bits(entropy) + checksum  # total bits = ENT + CS
    # Split into 11-bit indices
    indices = [_bits_to_int(bits[i:i+11]) for i in range(0, len(bits), 11)]
    words = [wordlist[i] for i in indices]
    return " ".join(words)


def validate_mnemonic(mnemonic: str, wordlist: list[str]) -> tuple[bool, str]:
    """
    Validate words exist in list AND checksum is correct.
    Returns (is_valid, message)
    """
    words = [w.strip().lower() for w in mnemonic.split() if w.strip()]
    if len(words) not in (12, 15, 18, 21, 24):
        return False, "Invalid length: mnemonic must have 12/15/18/21/24 words."

    # Check all words exist
    try:
        indices = [wordlist.index(w) for w in words]
    except ValueError as e:
        bad = str(e).split("'")[1] if "'" in str(e) else "unknown"
        return False, f"Word not in BIP-39 English list: {bad}"

    # Build bitstring
    bits = "".join(f"{i:011b}" for i in indices)

    # Split entropy and checksum
    entropy_bits = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}[len(words)]
    cs_len = entropy_bits // 32
    ent_bits_str = bits[:entropy_bits]
    cs_bits_str = bits[entropy_bits:entropy_bits + cs_len]

    # Rebuild entropy bytes
    entropy_bytes = int(ent_bits_str, 2).to_bytes(entropy_bits // 8, byteorder="big")
    hash_bits = _bytes_to_bits(_sha256(entropy_bytes))
    expected_cs = hash_bits[:cs_len]

    if cs_bits_str != expected_cs:
        return False, "Checksum mismatch: mnemonic is NOT valid."
    return True, "Valid BIP-39 mnemonic (English) ✅"


def prompt_int(prompt: str, min_v: int, max_v: int) -> int:
    while True:
        s = input(prompt).strip()
        try:
            v = int(s)
            if min_v <= v <= max_v:
                return v
        except ValueError:
            pass
        print(f"Please enter a number between {min_v} and {max_v}.")


def main():
    print("=== BIP-39 Offline Tool (English) ===")
    print("Make sure 'english.txt' is in this folder.\n")

    try:
        wordlist = load_wordlist()
    except Exception as e:
        print(f"[ERROR] {e}")
        input("\nPress Enter to exit...")
        return

    while True:
        print("\nMenu:")
        print("1) Generate mnemonic(s) (valid checksum)")
        print("2) Validate a mnemonic")
        print("3) Exit")

        choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            print("\nGenerate mnemonic(s):")
            print("   1) 12 words")
            print("   2) 24 words")
            wchoice = input("Choose (1-2): ").strip()
            num_words = 12 if wchoice == "1" else 24 if wchoice == "2" else None
            if num_words is None:
                print("Invalid selection.")
                continue

            count = prompt_int("How many phrases to generate? (1-1000): ", 1, 1000)

            default_name = f"mnemonics_{num_words}w.txt"
            out_name = input(f"Output filename (Enter for '{default_name}'): ").strip() or default_name
            out_path = Path(out_name)

            phrases = [generate_mnemonic(num_words, wordlist) for _ in range(count)]

            # Auto-save
            out_path.write_text("\n".join(phrases) + "\n", encoding="utf-8")

            print(f"\nSaved {count} phrase(s) to: {out_path.resolve()}")
            print("First phrase preview:")
            print(phrases[0])

        elif choice == "2":
            print("\nPaste the mnemonic to validate (words separated by spaces).")
            mnemonic = input("> ").strip()
            ok, msg = validate_mnemonic(mnemonic, wordlist)
            print(msg)

        elif choice == "3":
            print("Bye.")
            break
        else:
            print("Invalid option. Choose 1, 2, or 3.")


if __name__ == "__main__":
    main()
