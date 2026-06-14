#!/usr/bin/env python3
"""Secure file steganography CLI.

Workflow:
1) Zip input file/folder
2) Encrypt zip file with AES-256-CBC + HMAC-SHA256 (PBKDF2-derived keys)
3) Embed encrypted payload into PNG using streaming LSB writes via img.load()
4) Extract + decrypt + recover zip (optionally unpack)
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import math
import os
import struct
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Iterable, Iterator, Optional, Tuple

from PIL import Image
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"STEG1"
VERSION = 1
SALT_LEN = 16
IV_LEN = 16
TAG_LEN = 32
HEADER_FMT = ">5sBQ"  # magic, version, encrypted_len
HEADER_SIZE = struct.calcsize(HEADER_FMT)
KDF_ITERATIONS = 600_000
CHUNK_SIZE = 1024 * 1024  # 1 MiB streaming chunk


class StegError(Exception):
    """Raised on expected operational failures."""


def _derive_key_material(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        KDF_ITERATIONS,
        dklen=80,  # 32 bytes enc key + 32 bytes mac key + 16 bytes IV
    )


def _iter_file_chunks(path: Path, chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


def _iter_bits_from_chunks(chunks: Iterable[bytes]) -> Iterator[int]:
    for chunk in chunks:
        for byte in chunk:
            for shift in range(7, -1, -1):
                yield (byte >> shift) & 1


def _encrypt_file_cbc(in_path: Path, out_path: Path, enc_key: bytes, iv: bytes) -> None:
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    with in_path.open("rb") as src, out_path.open("wb") as dst:
        while True:
            chunk = src.read(CHUNK_SIZE)
            if not chunk:
                break
            padded = padder.update(chunk)
            if padded:
                dst.write(encryptor.update(padded))

        final_padded = padder.finalize()
        if final_padded:
            dst.write(encryptor.update(final_padded))
        dst.write(encryptor.finalize())


def _decrypt_file_cbc(in_path: Path, out_path: Path, enc_key: bytes, iv: bytes) -> None:
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    try:
        with in_path.open("rb") as src, out_path.open("wb") as dst:
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                plaintext = unpadder.update(decryptor.update(chunk))
                if plaintext:
                    dst.write(plaintext)

            final_plaintext = unpadder.update(decryptor.finalize()) + unpadder.finalize()
            if final_plaintext:
                dst.write(final_plaintext)
    except ValueError as exc:
        raise StegError("Decrypt failed: password incorrect or payload corrupted") from exc


def _hmac_for_iv_and_file(iv: bytes, path: Path, mac_key: bytes) -> bytes:
    digest = hmac.new(mac_key, digestmod=hashlib.sha256)
    digest.update(iv)
    for chunk in _iter_file_chunks(path):
        digest.update(chunk)
    return digest.digest()


def _encrypt_file_to_blob(input_file: Path, blob_file: Path, password: str) -> int:
    salt = os.urandom(SALT_LEN)
    km = _derive_key_material(password, salt)
    enc_key = km[:32]
    mac_key = km[32:64]
    iv = km[64:80]

    with tempfile.TemporaryDirectory(prefix="steg_enc_") as tmp:
        tmp_dir = Path(tmp)
        cipher_file = tmp_dir / "cipher.bin"
        _encrypt_file_cbc(input_file, cipher_file, enc_key, iv)
        tag = _hmac_for_iv_and_file(iv, cipher_file, mac_key)

        with blob_file.open("wb") as out:
            out.write(salt)
            out.write(iv)
            out.write(tag)
            for chunk in _iter_file_chunks(cipher_file):
                out.write(chunk)

    return blob_file.stat().st_size


def _decrypt_blob_to_file(blob_file: Path, output_file: Path, password: str) -> None:
    min_len = SALT_LEN + IV_LEN + TAG_LEN + 16
    blob_size = blob_file.stat().st_size
    if blob_size < min_len:
        raise StegError("Encrypted payload is too short or corrupted")

    with blob_file.open("rb") as f:
        salt = f.read(SALT_LEN)
        iv = f.read(IV_LEN)
        tag = f.read(TAG_LEN)
        if len(salt) != SALT_LEN or len(iv) != IV_LEN or len(tag) != TAG_LEN:
            raise StegError("Encrypted payload is too short or corrupted")

        km = _derive_key_material(password, salt)
        enc_key = km[:32]
        mac_key = km[32:64]

        digest = hmac.new(mac_key, digestmod=hashlib.sha256)
        digest.update(iv)

        with tempfile.TemporaryDirectory(prefix="steg_dec_") as tmp:
            tmp_dir = Path(tmp)
            cipher_file = tmp_dir / "cipher.bin"
            with cipher_file.open("wb") as cipher_out:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    digest.update(chunk)
                    cipher_out.write(chunk)

            if not hmac.compare_digest(tag, digest.digest()):
                raise StegError("Decrypt failed: password incorrect or payload corrupted")

            _decrypt_file_cbc(cipher_file, output_file, enc_key, iv)


def encrypt_bytes(data: bytes, password: str) -> bytes:
    # Backward-compatible helper; uses temp files but still returns bytes.
    with tempfile.TemporaryDirectory(prefix="steg_bytes_enc_") as tmp:
        tmp_dir = Path(tmp)
        plain = tmp_dir / "plain.bin"
        blob = tmp_dir / "blob.bin"
        plain.write_bytes(data)
        _encrypt_file_to_blob(plain, blob, password)
        return blob.read_bytes()


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    # Backward-compatible helper; uses temp files but still returns bytes.
    with tempfile.TemporaryDirectory(prefix="steg_bytes_dec_") as tmp:
        tmp_dir = Path(tmp)
        blob_file = tmp_dir / "blob.bin"
        out_file = tmp_dir / "plain.bin"
        blob_file.write_bytes(blob)
        _decrypt_blob_to_file(blob_file, out_file, password)
        return out_file.read_bytes()


def make_zip(input_path: Path, zip_path: Path) -> None:
    input_path = input_path.resolve()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if input_path.is_file():
            zf.write(input_path, arcname=input_path.name)
            return
        if not input_path.is_dir():
            raise StegError(f"Input path not found: {input_path}")
        base_parent = input_path.parent
        for root, _, files in os.walk(input_path):
            root_path = Path(root)
            for name in files:
                abs_file = root_path / name
                arcname = abs_file.relative_to(base_parent)
                zf.write(abs_file, arcname=str(arcname))


def unpack_zip(zip_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(out_dir)


def _resample_filter():
    if hasattr(Image, "Resampling"):
        return Image.Resampling.LANCZOS
    return Image.LANCZOS


def _auto_upscale_for_capacity(rgb_img: Image.Image, required_bits: int) -> Tuple[Image.Image, bool]:
    width, height = rgb_img.size
    current_pixels = width * height
    current_capacity = current_pixels * 3
    if current_capacity >= required_bits:
        return rgb_img, False

    required_pixels = (required_bits + 2) // 3
    scale = math.sqrt(required_pixels / current_pixels)
    scale *= 1.01  # margin for rounding
    new_w = max(1, math.ceil(width * scale))
    new_h = max(1, math.ceil(height * scale))

    resized = rgb_img.resize((new_w, new_h), resample=_resample_filter())
    while (new_w * new_h * 3) < required_bits:
        new_w += 1
        new_h += 1
        resized = resized.resize((new_w, new_h), resample=_resample_filter())

    return resized, True


def _iter_payload_chunks(header: bytes, payload_file: Path) -> Iterator[bytes]:
    yield header
    yield from _iter_file_chunks(payload_file)


def embed_payload_from_file(cover_png: Path, out_png: Path, payload_file: Path, payload_size: int) -> None:
    img = Image.open(cover_png)
    rgb_img = img.convert("RGB")

    required_bits = payload_size * 8
    rgb_img, _ = _auto_upscale_for_capacity(rgb_img, required_bits)
    px = rgb_img.load()
    width, height = rgb_img.size

    header = struct.pack(HEADER_FMT, MAGIC, VERSION, payload_file.stat().st_size)
    bit_iter = _iter_bits_from_chunks(_iter_payload_chunks(header, payload_file))

    done = False
    for y in range(height):
        for x in range(width):
            r, g, b = px[x, y]
            channels = [r, g, b]
            for i in range(3):
                try:
                    bit = next(bit_iter)
                except StopIteration:
                    done = True
                    break
                channels[i] = (channels[i] & 0xFE) | bit
            px[x, y] = (channels[0], channels[1], channels[2])
            if done:
                break
        if done:
            break

    if not done:
        # If capacity is exactly filled, iterator may already be exhausted without
        # entering the StopIteration branch. Verify no trailing bits remain.
        if next(bit_iter, None) is not None:
            raise StegError("Cover image does not have enough capacity for payload")

    rgb_img.save(out_png, format="PNG")


def embed_payload(cover_png: Path, out_png: Path, payload: bytes) -> None:
    # Backward-compatible helper.
    with tempfile.TemporaryDirectory(prefix="steg_embed_bytes_") as tmp:
        payload_file = Path(tmp) / "payload.bin"
        payload_file.write_bytes(payload)
        embed_payload_from_file(cover_png, out_png, payload_file, len(payload))


def _iter_lsb_bits(img: Image.Image) -> Iterator[int]:
    rgb = img.convert("RGB")
    px = rgb.load()
    width, height = rgb.size
    for y in range(height):
        for x in range(width):
            r, g, b = px[x, y]
            yield r & 1
            yield g & 1
            yield b & 1


def _iter_lsb_bytes(img: Image.Image) -> Iterator[int]:
    acc = 0
    bit_count = 0
    for bit in _iter_lsb_bits(img):
        acc = (acc << 1) | bit
        bit_count += 1
        if bit_count == 8:
            yield acc
            acc = 0
            bit_count = 0


def _read_exact_bytes(byte_iter: Iterator[int], n: int) -> bytes:
    out = bytearray()
    for _ in range(n):
        b = next(byte_iter, None)
        if b is None:
            raise StegError("Image does not contain enough embedded data")
        out.append(b)
    return bytes(out)


def extract_payload_to_file(stego_png: Path, out_payload_file: Path) -> int:
    img = Image.open(stego_png)
    byte_iter = _iter_lsb_bytes(img)

    header = _read_exact_bytes(byte_iter, HEADER_SIZE)
    magic, version, enc_len = struct.unpack(HEADER_FMT, header)
    if magic != MAGIC:
        raise StegError("Magic header mismatch: no valid payload found")
    if version != VERSION:
        raise StegError(f"Unsupported payload version: {version}")

    remaining = enc_len
    with out_payload_file.open("wb") as out:
        while remaining > 0:
            chunk_len = min(CHUNK_SIZE, remaining)
            chunk = bytearray()
            for _ in range(chunk_len):
                b = next(byte_iter, None)
                if b is None:
                    raise StegError("Image does not contain enough embedded data")
                chunk.append(b)
            out.write(chunk)
            remaining -= chunk_len

    return enc_len


def extract_payload(stego_png: Path) -> bytes:
    # Backward-compatible helper.
    with tempfile.TemporaryDirectory(prefix="steg_extract_bytes_") as tmp:
        payload_file = Path(tmp) / "payload.bin"
        extract_payload_to_file(stego_png, payload_file)
        return payload_file.read_bytes()


def build_payload(encrypted_blob: bytes) -> bytes:
    # Backward-compatible helper.
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, len(encrypted_blob))
    return header + encrypted_blob


def hide_flow(input_path: Path, cover_png: Path, out_png: Path, password: str) -> None:
    with tempfile.TemporaryDirectory(prefix="steg_secure_") as tmp:
        tmp_dir = Path(tmp)
        zip_path = tmp_dir / "payload.zip"
        encrypted_blob_path = tmp_dir / "encrypted_blob.bin"

        make_zip(input_path, zip_path)
        encrypted_size = _encrypt_file_to_blob(zip_path, encrypted_blob_path, password)
        payload_size = HEADER_SIZE + encrypted_size
        embed_payload_from_file(cover_png, out_png, encrypted_blob_path, payload_size)


def reveal_flow(stego_png: Path, out_dir: Path, password: str, auto_unpack: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    recovered_zip = out_dir / "recovered_payload.zip"
    with tempfile.TemporaryDirectory(prefix="steg_reveal_") as tmp:
        tmp_dir = Path(tmp)
        encrypted_blob_path = tmp_dir / "encrypted_blob.bin"

        extract_payload_to_file(stego_png, encrypted_blob_path)
        _decrypt_blob_to_file(encrypted_blob_path, recovered_zip, password)

    if auto_unpack:
        unpack_dir = out_dir / "recovered_files"
        unpack_zip(recovered_zip, unpack_dir)


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AES-256 + LSB secure steganography")
    sub = parser.add_subparsers(dest="cmd", required=True)

    hide = sub.add_parser("hide", help="Compress + encrypt + embed into PNG")
    hide.add_argument("--input", required=True, type=Path, help="File or folder to hide")
    hide.add_argument("--cover", required=True, type=Path, help="Cover PNG path")
    hide.add_argument("--output", required=True, type=Path, help="Output stego PNG path")
    hide.add_argument("--password", required=True, help="Encryption password")

    reveal = sub.add_parser("reveal", help="Extract + decrypt from stego PNG")
    reveal.add_argument("--input", required=True, type=Path, help="Stego PNG path")
    reveal.add_argument("--output-dir", required=True, type=Path, help="Output folder")
    reveal.add_argument("--password", required=True, help="Encryption password")
    reveal.add_argument(
        "--unpack",
        action="store_true",
        help="Also extract recovered ZIP into output-dir/recovered_files",
    )

    return parser.parse_args(list(argv))


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    try:
        if args.cmd == "hide":
            hide_flow(args.input, args.cover, args.output, args.password)
            print(f"[OK] Stego image written: {args.output}")
        elif args.cmd == "reveal":
            reveal_flow(args.input, args.output_dir, args.password, args.unpack)
            print(f"[OK] Recovery completed in: {args.output_dir}")
        else:
            raise StegError(f"Unknown command: {args.cmd}")
    except StegError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"[ERROR] File not found: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
