from __future__ import annotations

import argparse
import ctypes
import os
import string
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


BUFFER_SIZE = 1024 * 1024


@dataclass(frozen=True)
class FileSignature:
    name: str
    extension: str
    header: bytes
    footer: bytes | None
    default_max_bytes: int


@dataclass(frozen=True)
class RecoveryResult:
    path: Path
    bytes_written: int
    confidence_percent: int
    extra_stream_bytes_read: int
    initial_bytes_consumed: int


SIGNATURES: tuple[FileSignature, ...] = (
    FileSignature("jpeg", ".jpg", b"\xff\xd8\xff", b"\xff\xd9", 64 * 1024 * 1024),
    FileSignature("png", ".png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", 64 * 1024 * 1024),
    FileSignature("pdf", ".pdf", b"%PDF-", b"%%EOF", 128 * 1024 * 1024),
    FileSignature("gif", ".gif", b"GIF8", b"\x00\x3b", 32 * 1024 * 1024),
    FileSignature("zip-office", ".zip", b"PK\x03\x04", b"PK\x05\x06", 256 * 1024 * 1024),
)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Windows Data Recovery MVP")
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("list", help="List likely Windows drive scan targets")

    scan = subcommands.add_parser("scan", help="Run a read-only deep signature scan")
    scan.add_argument("--source", required=True, help=r'Device path like \\.\E: or an image file path')
    scan.add_argument("--output", required=True, help="Folder on a different drive for recovered files")
    scan.add_argument("--max-file-mb", type=int, default=256, help="Maximum bytes to carve per candidate, in MB")
    scan.add_argument("--max-candidates", type=int, default=0, help="Stop after this many recovered candidates; 0 means no limit")
    scan.add_argument("--types", default="all", help="Comma-separated types: jpeg,png,pdf,gif,zip-office or all")
    scan.add_argument("--min-bytes", type=int, default=0, help="Delete and ignore recovered candidates smaller than this many bytes")

    args = parser.parse_args(argv)

    if args.command == "list":
        return list_drives()

    if args.command == "scan":
        signatures = select_signatures(args.types)
        if not signatures:
            print("No valid file types selected. Use jpeg,png,pdf,gif,zip-office or all.", file=sys.stderr)
            return 2
        return scan_source(
            args.source,
            Path(args.output),
            max(1, args.max_file_mb) * 1024 * 1024,
            max(0, args.max_candidates),
            signatures,
            max(0, args.min_bytes),
        )

    parser.print_help()
    return 2


def list_drives() -> int:
    if os.name != "nt":
        print("Drive listing is Windows-specific. You can still scan a disk image file.", file=sys.stderr)
        return 1

    kernel32 = ctypes.windll.kernel32
    bitmask = kernel32.GetLogicalDrives()

    drive_types = {
        0: "Unknown",
        1: "NoRootDir",
        2: "Removable",
        3: "Fixed",
        4: "Network",
        5: "CD/DVD",
        6: "RAMDisk",
    }

    for index, letter in enumerate(string.ascii_uppercase):
        if not bitmask & (1 << index):
            continue

        root = f"{letter}:\\"
        dtype = kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
        total = ctypes.c_ulonglong(0)
        free = ctypes.c_ulonglong(0)
        ok = kernel32.GetDiskFreeSpaceExW(
            ctypes.c_wchar_p(root),
            None,
            ctypes.byref(total),
            ctypes.byref(free),
        )
        size_text = f"{format_bytes(free.value)} free / {format_bytes(total.value)}" if ok else "not ready"
        print(f"{root:<6} {drive_types.get(dtype, 'Unknown'):<10} {size_text}")
        print(f"       scan source: \\\\.\\{letter}:")

    return 0


def scan_source(
    source: str,
    output_dir: Path,
    max_bytes_per_file: int,
    max_candidates: int,
    signatures: tuple[FileSignature, ...],
    min_bytes: int,
) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_looks_like_source(source, output_dir):
        print("Refusing to recover to the same drive/source. Choose an output folder on another disk.", file=sys.stderr)
        return 1

    print(f"Source: {source}")
    print(f"Output: {output_dir}")
    print("Mode: read-only deep signature scan")
    print(f"Types: {', '.join(sig.name for sig in signatures)}")
    if min_bytes:
        print(f"Minimum recovered size: {min_bytes} bytes")
    print()

    with open_source_readonly(source) as stream:
        count = SignatureScanner(signatures).scan(stream, output_dir, max_bytes_per_file, max_candidates, min_bytes)

    print()
    print(f"Recovered candidates: {count}")
    print("Review confidence percentages before trusting restored files.")
    return 0


def select_signatures(types_text: str) -> tuple[FileSignature, ...]:
    requested = {item.strip().lower() for item in types_text.split(",") if item.strip()}
    if not requested or "all" in requested:
        return SIGNATURES
    return tuple(sig for sig in SIGNATURES if sig.name in requested or sig.extension.lstrip(".") in requested)


def open_source_readonly(source: str) -> BinaryIO:
    try:
        return open(source, "rb", buffering=BUFFER_SIZE)
    except PermissionError as exc:
        raise PermissionError(f"Could not open {source!r}. Run the terminal as Administrator for live drives.") from exc


def output_looks_like_source(source: str, output_dir: Path) -> bool:
    output_drive = output_dir.resolve().drive.upper()
    if not output_drive:
        return False

    if source.lower().startswith("\\\\.\\"):
        normalized = source.replace("/", "\\")
        if len(normalized) >= 6 and normalized[4].isalpha():
            return f"{normalized[4].upper()}:" == output_drive
        return False

    try:
        source_path = Path(source).resolve()
        output_path = output_dir.resolve()
        return source_path == output_path or source_path in output_path.parents
    except OSError:
        return False


class SignatureScanner:
    def __init__(self, signatures: tuple[FileSignature, ...]) -> None:
        self.signatures = signatures
        self.max_signature_length = max(max(len(sig.header), len(sig.footer or b"")) for sig in signatures)

    def scan(self, source: BinaryIO, output_dir: Path, max_bytes_per_file: int, max_candidates: int, min_bytes: int) -> int:
        carry = b""
        absolute_offset = 0
        recovered = 0
        next_progress_at = 256 * 1024 * 1024

        while True:
            chunk = source.read(BUFFER_SIZE)
            if not chunk:
                break

            block = carry + chunk
            recovered_from_block = False
            index = 0
            scan_limit = max(0, len(block) - self.max_signature_length)

            while index <= scan_limit:
                signature = self._find_header(block, index)
                if signature is None:
                    index += 1
                    continue

                file_offset = absolute_offset + index - len(carry)
                if file_offset < 0:
                    index += 1
                    continue

                if max_candidates and recovered >= max_candidates:
                    print(f"Stopped after --max-candidates {max_candidates}.")
                    return recovered

                limit = min(max_bytes_per_file, signature.default_max_bytes)
                result = self._recover_candidate(source, block[index:], signature, output_dir, file_offset, limit, recovered + 1)
                if min_bytes and result.bytes_written < min_bytes:
                    result.path.unlink(missing_ok=True)
                    index += max(1, result.initial_bytes_consumed)
                    continue

                recovered += 1
                print_recovery_result(result, signature, file_offset)

                if result.extra_stream_bytes_read == 0:
                    index += max(1, result.initial_bytes_consumed)
                    continue

                absolute_offset += len(chunk) + result.extra_stream_bytes_read
                carry = b""
                recovered_from_block = True
                break

            if absolute_offset >= next_progress_at:
                print(f"Progress: scanned about {format_bytes(absolute_offset)}; recovered {recovered} candidates")
                while absolute_offset >= next_progress_at:
                    next_progress_at += 256 * 1024 * 1024

            if recovered_from_block:
                continue

            carry = block[-self.max_signature_length :]
            absolute_offset += len(chunk)

        return recovered

    def _find_header(self, block: bytes, index: int) -> FileSignature | None:
        for signature in self.signatures:
            if block.startswith(signature.header, index):
                return signature
        return None

    def _recover_candidate(
        self,
        source: BinaryIO,
        initial_bytes: bytes,
        signature: FileSignature,
        output_dir: Path,
        file_offset: int,
        max_bytes: int,
        index: int,
    ) -> RecoveryResult:
        path = output_dir / f"{index:06d}_{signature.name}_{file_offset:X}{signature.extension}"
        written = 0
        extra_stream_bytes_read = 0
        initial_bytes_consumed = 0
        footer_found = False
        tail: deque[int] = deque(maxlen=len(signature.footer or b""))

        with path.open("xb") as output:
            written, footer_found, initial_bytes_consumed = write_recovery_chunk(output, initial_bytes, tail, signature, written, max_bytes)

            while written < max_bytes and not footer_found:
                wanted = min(64 * 1024, max_bytes - written)
                chunk = source.read(wanted)
                if not chunk:
                    break

                extra_stream_bytes_read += len(chunk)
                just_written, footer_found, _ = write_recovery_chunk(output, chunk, tail, signature, written, max_bytes)
                written = just_written

        return RecoveryResult(path, written, estimate_confidence(signature, footer_found, written, max_bytes), extra_stream_bytes_read, initial_bytes_consumed)


def write_recovery_chunk(
    output: BinaryIO,
    chunk: bytes,
    tail: deque[int],
    signature: FileSignature,
    already_written: int,
    max_bytes: int,
) -> tuple[int, bool, int]:
    allowed = max_bytes - already_written
    chunk = chunk[:allowed]
    write_count = len(chunk)
    footer_found = False

    if signature.footer:
        footer_end = find_footer_end(chunk, tail, signature.footer)
        if footer_end is not None:
            write_count = footer_end + 1
            footer_found = True

    output.write(chunk[:write_count])
    return already_written + write_count, footer_found, write_count


def find_footer_end(chunk: bytes, tail: deque[int], footer: bytes) -> int | None:
    for index, byte in enumerate(chunk):
        tail.append(byte)
        if len(tail) == len(footer) and bytes(tail) == footer:
            return index
    return None


def print_recovery_result(result: RecoveryResult, signature: FileSignature, file_offset: int) -> None:
    print(
        f"{result.path.name:<32} {signature.name:<10} "
        f"offset=0x{file_offset:X} confidence={result.confidence_percent}% "
        f"bytes={result.bytes_written}"
    )


def estimate_confidence(signature: FileSignature, footer_found: bool, written: int, max_bytes: int) -> int:
    if footer_found:
        return 70 if signature.name == "zip-office" else 85
    if written >= max_bytes:
        return 35
    return 50


def format_bytes(value: int) -> str:
    units = ("B", "KB", "MB", "GB", "TB")
    size = float(value)
    unit = 0
    while size >= 1024 and unit < len(units) - 1:
        size /= 1024
        unit += 1
    return f"{size:.2f} {units[unit]}"


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
