#!/usr/bin/env python3
"""Validate or generate a MetaMask (BIP-39) seed phrase."""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from dataclasses import dataclass
from typing import List

WORDLIST_FILE = os.path.join(os.path.dirname(__file__), "wordlist_english.txt")

ALLOWED_WORD_COUNTS = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}


class ValidationError(Exception):
    pass


@dataclass(frozen=True)
class ValidationDetails:
    words: List[str]
    indices: List[int]
    entropy_bits_len: int
    checksum_bits_len: int


def load_wordlist() -> List[str]:
    if not os.path.exists(WORDLIST_FILE):
        raise ValidationError(f"No se encontró el archivo de wordlist: {WORDLIST_FILE}")
    with open(WORDLIST_FILE, "r", encoding="utf-8") as handle:
        words = [line.strip() for line in handle if line.strip()]
    if len(words) != 2048:
        raise ValidationError("La wordlist debe contener 2048 palabras.")
    if len(set(words)) != 2048:
        raise ValidationError("La wordlist contiene palabras duplicadas.")
    return words


def normalize_phrase(phrase: str) -> List[str]:
    cleaned = " ".join(phrase.strip().lower().split())
    if not cleaned:
        raise ValidationError("La frase no puede estar vacía.")
    return cleaned.split(" ")


def _bits_from_indices(indices: List[int]) -> str:
    return "".join(f"{index:011b}" for index in indices)


def _bits_to_bytes(bits: str) -> bytes:
    return int(bits, 2).to_bytes(len(bits) // 8, byteorder="big")


def _bytes_to_bits(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def validate_phrase(phrase: str, wordlist: List[str]) -> ValidationDetails:
    words = normalize_phrase(phrase)
    if len(words) not in ALLOWED_WORD_COUNTS:
        raise ValidationError(
            "La frase debe tener 12, 15, 18, 21 o 24 palabras (BIP-39)."
        )

    word_to_index = {word: idx for idx, word in enumerate(wordlist)}
    try:
        indices = [word_to_index[word] for word in words]
    except KeyError as exc:
        raise ValidationError(f"La palabra '{exc.args[0]}' no existe en la wordlist.")

    bits = _bits_from_indices(indices)
    total_bits = len(bits)
    checksum_bits_len = total_bits // 33
    entropy_bits_len = total_bits - checksum_bits_len

    entropy_bits = bits[:entropy_bits_len]
    checksum_bits = bits[entropy_bits_len:]

    entropy_bytes = _bits_to_bytes(entropy_bits)
    digest = hashlib.sha256(entropy_bytes).digest()
    digest_bits = _bytes_to_bits(digest)
    expected_checksum = digest_bits[:checksum_bits_len]

    if checksum_bits != expected_checksum:
        raise ValidationError("El checksum no coincide: la frase no es válida.")

    return ValidationDetails(
        words=words,
        indices=indices,
        entropy_bits_len=entropy_bits_len,
        checksum_bits_len=checksum_bits_len,
    )


def generate_phrase(word_count: int, wordlist: List[str]) -> str:
    if word_count not in ALLOWED_WORD_COUNTS:
        raise ValidationError(
            "La frase debe tener 12, 15, 18, 21 o 24 palabras (BIP-39)."
        )

    entropy_bits_len = ALLOWED_WORD_COUNTS[word_count]
    entropy_bytes_len = entropy_bits_len // 8
    entropy = os.urandom(entropy_bytes_len)
    entropy_bits = _bytes_to_bits(entropy)

    checksum_bits_len = entropy_bits_len // 32
    digest = hashlib.sha256(entropy).digest()
    checksum_bits = _bytes_to_bits(digest)[:checksum_bits_len]

    combined_bits = entropy_bits + checksum_bits
    indices = [int(combined_bits[i : i + 11], 2) for i in range(0, len(combined_bits), 11)]
    words = [wordlist[index] for index in indices]
    return " ".join(words)


def _prompt_input(message: str) -> str:
    return input(message).strip()


def _display_details(details: ValidationDetails) -> None:
    print("\nDetalles de validación:")
    print(f"- Palabras: {len(details.words)}")
    print(f"- Entropía: {details.entropy_bits_len} bits")
    print(f"- Checksum: {details.checksum_bits_len} bits")
    print("- Índices (BIP-39):")
    print(", ".join(str(index) for index in details.indices))


def run_menu(wordlist: List[str]) -> int:
    while True:
        print("\n=== Menú MetaMask (BIP-39) ===")
        print("1) Validar una frase")
        print("2) Generar una frase nueva")
        print("3) Validar y mostrar detalles")
        print("4) Salir")
        choice = _prompt_input("Selecciona una opción (1-4): ")

        if choice == "1":
            phrase = _prompt_input("Ingresa la frase semilla: ")
            try:
                validate_phrase(phrase, wordlist)
            except ValidationError as exc:
                print(f"❌ {exc}")
                continue
            print("✅ La frase es válida según BIP-39 (MetaMask).")
        elif choice == "2":
            count_raw = _prompt_input("Cantidad de palabras (12/15/18/21/24): ")
            try:
                count = int(count_raw)
                phrase = generate_phrase(count, wordlist)
            except (ValueError, ValidationError) as exc:
                print(f"❌ {exc}")
                continue
            print("✅ Frase generada (BIP-39):")
            print(phrase)
        elif choice == "3":
            phrase = _prompt_input("Ingresa la frase semilla: ")
            try:
                details = validate_phrase(phrase, wordlist)
            except ValidationError as exc:
                print(f"❌ {exc}")
                continue
            print("✅ La frase es válida según BIP-39 (MetaMask).")
            _display_details(details)
        elif choice == "4":
            return 0
        else:
            print("❌ Opción inválida. Intenta de nuevo.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Valida o genera una frase semilla de MetaMask (BIP-39)."
    )
    parser.add_argument(
        "phrase",
        nargs="*",
        help="Frase semilla entre comillas, por ejemplo: 'abandon ... about'",
    )
    parser.add_argument(
        "--generate",
        type=int,
        choices=sorted(ALLOWED_WORD_COUNTS.keys()),
        help="Genera una frase con N palabras (12/15/18/21/24).",
    )
    parser.add_argument(
        "--menu",
        action="store_true",
        help="Abre un menú interactivo para validar o generar frases.",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="Muestra detalles de validación (entropía, checksum e índices).",
    )
    args = parser.parse_args()

    try:
        wordlist = load_wordlist()

        if args.menu:
            return run_menu(wordlist)

        if args.generate:
            phrase = generate_phrase(args.generate, wordlist)
            print("✅ Frase generada (BIP-39):")
            print(phrase)
            return 0

        phrase = " ".join(args.phrase).strip()
        if not phrase:
            phrase = input("Ingresa la frase semilla: ").strip()

        details = validate_phrase(phrase, wordlist)
        print("✅ La frase es válida según BIP-39 (MetaMask).")
        if args.details:
            _display_details(details)
        return 0
    except ValidationError as exc:
        print(f"❌ {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
