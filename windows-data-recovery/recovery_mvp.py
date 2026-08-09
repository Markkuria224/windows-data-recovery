from __future__ import annotations

import argparse
import binascii
import ctypes
import os
import re
import string
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol


BUFFER_SIZE = 1024 * 1024


@dataclass(frozen=True)
class FileSignature:
    name: str
    extension: str
    header: bytes
    footer: bytes | None
    default_max_bytes: int
    validator: FileValidator | None = None


@dataclass(frozen=True)
class RecoveryResult:
    path: Path
    bytes_written: int
    confidence_percent: int
    extra_stream_bytes_read: int
    initial_bytes_consumed: int
    file_type: str
    validation_score: float
    validation_reason: str


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    score: float
    reason: str


class FileValidator(Protocol):
    def validate(self, data: bytes) -> ValidationResult:
        ...


class ConfidenceScorer:
    def __init__(self, weights: dict[str, int]) -> None:
        self.weights = weights
        self.max_score = sum(weights.values())

    def score(self, evidence: dict[str, bool]) -> tuple[float, list[str]]:
        messages: list[str] = []
        total = 0
        for name, weight in self.weights.items():
            if evidence.get(name, False):
                total += weight
                messages.append(name)
        score = total / self.max_score if self.max_score else 0.0
        return score, messages


class JPEGValidator:
    WEIGHTS = {
        "has_header": 20,
        "has_footer": 20,
        "valid_markers": 30,
        "valid_segment_lengths": 20,
        "reasonable_size": 10,
    }

    def __init__(self) -> None:
        self.scorer = ConfidenceScorer(self.WEIGHTS)

    def validate(self, data: bytes) -> ValidationResult:
        if len(data) < 4 or data[:2] != b"\xff\xd8":
            return ValidationResult(False, 0.0, "Missing JPEG SOI")

        evidence: dict[str, bool] = {
            "has_header": True,
            "has_footer": data.endswith(b"\xff\xd9"),
            "valid_markers": False,
            "valid_segment_lengths": False,
            "reasonable_size": len(data) >= 16,
        }

        if not evidence["has_footer"]:
            score, messages = self.scorer.score(evidence)
            return ValidationResult(False, score, "Missing JPEG EOI")

        parse_result = self._parse_markers(data)
        if not parse_result[0]:
            return ValidationResult(False, 0.0, parse_result[1])

        evidence["valid_markers"] = True
        evidence["valid_segment_lengths"] = parse_result[2]

        score, messages = self.scorer.score(evidence)
        reason = "JPEG validation: " + ", ".join(messages)
        return ValidationResult(True, score, reason)

    def _parse_markers(self, data: bytes) -> tuple[bool, str, bool]:
        pos = 2
        valid_lengths = True
        while pos < len(data) - 1:
            if data[pos] != 0xFF:
                pos += 1
                continue

            pos += 1
            while pos < len(data) and data[pos] == 0xFF:
                pos += 1
            if pos >= len(data):
                return False, "Truncated marker", False

            marker = data[pos]
            pos += 1

            if marker == 0xD9:
                return True, "Found EOI", valid_lengths

            if marker == 0xD8:
                continue
            if marker == 0x01 or 0xD0 <= marker <= 0xD7:
                continue

            if marker == 0xDA:
                scan_pos = pos
                while scan_pos < len(data) - 1:
                    if data[scan_pos] == 0xFF:
                        if data[scan_pos + 1] == 0x00:
                            scan_pos += 2
                            continue
                        if data[scan_pos + 1] == 0xD9:
                            return True, "Found EOI after SOS", valid_lengths
                    scan_pos += 1
                return False, "Missing EOI after SOS", False

            if pos + 2 > len(data):
                return False, "Invalid segment length header", False
            segment_length = int.from_bytes(data[pos:pos + 2], "big")
            if segment_length < 2 or pos + segment_length > len(data):
                return False, "Invalid JPEG segment length", False
            pos += segment_length

        return False, "Missing JPEG EOI", False


class PNGValidator:
    WEIGHTS = {
        "has_header": 20,
        "has_iend": 20,
        "valid_chunk_structure": 30,
        "valid_crc": 20,
        "reasonable_size": 10,
    }

    def __init__(self) -> None:
        self.scorer = ConfidenceScorer(self.WEIGHTS)

    def validate(self, data: bytes) -> ValidationResult:
        if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
            return ValidationResult(False, 0.0, "Missing PNG signature")

        evidence: dict[str, bool] = {
            "has_header": True,
            "has_iend": False,
            "valid_chunk_structure": False,
            "valid_crc": False,
            "reasonable_size": len(data) >= 32,
        }

        pos = 8
        valid_structure = True
        crc_ok = True
        has_iend = False

        while pos + 8 <= len(data):
            length = int.from_bytes(data[pos:pos + 4], "big")
            chunk_type = data[pos + 4:pos + 8]
            pos += 8
            if pos + length + 4 > len(data):
                valid_structure = False
                break

            chunk_data = data[pos:pos + length]
            pos += length
            crc_stored = int.from_bytes(data[pos:pos + 4], "big")
            pos += 4
            crc_calculated = binascii.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
            if crc_calculated != crc_stored:
                crc_ok = False
                valid_structure = False
                break

            if chunk_type == b"IEND":
                has_iend = True
                break

        evidence["has_iend"] = has_iend
        evidence["valid_chunk_structure"] = valid_structure and has_iend
        evidence["valid_crc"] = crc_ok and has_iend

        if not valid_structure:
            return ValidationResult(False, 0.0, "Invalid PNG chunk structure")

        if not has_iend:
            score, messages = self.scorer.score(evidence)
            return ValidationResult(False, score, "Missing IEND chunk")

        score, messages = self.scorer.score(evidence)
        return ValidationResult(True, score, "PNG validation: " + ", ".join(messages))


class PDFValidator:
    WEIGHTS = {
        "has_header": 25,
        "has_eof": 25,
        "has_startxref": 20,
        "has_xref": 20,
        "reasonable_size": 10,
    }

    def __init__(self) -> None:
        self.scorer = ConfidenceScorer(self.WEIGHTS)

    def validate(self, data: bytes) -> ValidationResult:
        if not data.startswith(b"%PDF-"):
            return ValidationResult(False, 0.0, "Missing PDF header")

        tail = data[-512:]
        evidence: dict[str, bool] = {
            "has_header": True,
            "has_eof": b"%%EOF" in tail,
            "has_startxref": b"startxref" in tail,
            "has_xref": b"xref" in data,
            "reasonable_size": len(data) >= 32,
        }

        if not evidence["has_eof"]:
            score, messages = self.scorer.score(evidence)
            return ValidationResult(False, score, "Missing %EOF")

        if not evidence["has_startxref"]:
            score, messages = self.scorer.score(evidence)
            return ValidationResult(False, score, "Missing startxref")

        score, messages = self.scorer.score(evidence)
        return ValidationResult(True, score, "PDF validation: " + ", ".join(messages))


class ZIPValidator:
    WEIGHTS = {
        "has_header": 20,
        "has_eocd": 25,
        "has_central_dir": 30,
        "valid_eocd": 15,
        "reasonable_size": 10,
    }

    def __init__(self) -> None:
        self.scorer = ConfidenceScorer(self.WEIGHTS)

    def validate(self, data: bytes) -> ValidationResult:
        if len(data) < 4 or not data.startswith(b"PK\x03\x04"):
            return ValidationResult(False, 0.0, "Missing ZIP local file header")

        evidence: dict[str, bool] = {
            "has_header": True,
            "has_eocd": False,
            "has_central_dir": False,
            "valid_eocd": False,
            "reasonable_size": len(data) >= 32,
        }

        eocd_pos = data.rfind(b"PK\x05\x06")
        if eocd_pos == -1:
            score, messages = self.scorer.score(evidence)
            return ValidationResult(False, score, "Missing EOCD")

        evidence["has_eocd"] = True
        if eocd_pos + 22 > len(data):
            return ValidationResult(False, 0.0, "Truncated EOCD")

        cd_size = int.from_bytes(data[eocd_pos + 12:eocd_pos + 16], "little")
        cd_offset = int.from_bytes(data[eocd_pos + 16:eocd_pos + 20], "little")
        evidence["valid_eocd"] = cd_offset + cd_size <= len(data)

        if cd_offset + 4 <= len(data) and data[cd_offset:cd_offset + 4] == b"PK\x01\x02":
            evidence["has_central_dir"] = True

        score, messages = self.scorer.score(evidence)
        valid = evidence["has_central_dir"] and evidence["valid_eocd"]
        return ValidationResult(valid, score, "ZIP validation: " + ", ".join(messages))


def get_validator_for_signature(signature: FileSignature) -> FileValidator | None:
    return signature.validator


SIGNATURES: tuple[FileSignature, ...] = (
    FileSignature("jpeg", ".jpg", b"\xff\xd8\xff", b"\xff\xd9", 64 * 1024 * 1024, JPEGValidator()),
    FileSignature("png", ".png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", 64 * 1024 * 1024, PNGValidator()),
    FileSignature("pdf", ".pdf", b"%PDF-", b"%%EOF", 128 * 1024 * 1024, PDFValidator()),
    FileSignature("gif", ".gif", b"GIF8", b"\x00\x3b", 32 * 1024 * 1024, None),
    FileSignature("zip-office", ".zip", b"PK\x03\x04", b"PK\x05\x06", 256 * 1024 * 1024, ZIPValidator()),
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


def _raw_device_drive(source: str) -> str | None:
    normalized = source.replace("/", "\\")
    match = re.match(r"^\\+\\\.\\+([A-Za-z]):", normalized)
    if match:
        return f"{match.group(1).upper()}:"
    return None


def output_looks_like_source(source: str, output_dir: Path) -> bool:
    output_path = output_dir.resolve(strict=False)
    output_drive = output_path.drive.upper()
    if not output_drive:
        return False

    raw_drive = _raw_device_drive(source)
    if raw_drive is not None:
        return output_drive == raw_drive

    try:
        source_path = Path(source).resolve(strict=False)
        source_is_dir = source_path.exists() and source_path.is_dir()
        if not source_is_dir and source.endswith(("\\", "/")):
            source_is_dir = True

        if source_path == output_path:
            return True

        if source_is_dir:
            return output_path in source_path.parents or source_path in output_path.parents

        return output_path == source_path.parent
    except OSError:
        return False


class SignatureScanner:
    def __init__(self, signatures: tuple[FileSignature, ...]) -> None:
        self.signatures = signatures
        self.max_signature_length = max(max(len(sig.header), len(sig.footer or b"")) for sig in signatures)
        self.max_header_length = max(len(sig.header) for sig in signatures)
        self.min_header_length = min(len(sig.header) for sig in signatures)
        self.header_overlap = max(1, self.max_header_length - 1)

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
            scan_limit = max(0, len(block) - self.min_header_length)

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
                    if result.extra_stream_bytes_read:
                        absolute_offset += len(chunk) + result.extra_stream_bytes_read
                        carry = b""
                        recovered_from_block = True
                        break
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

            carry = block[-self.header_overlap :]
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
        recovered_data = bytearray()

        with path.open("xb") as output:
            written, footer_found, initial_bytes_consumed = write_recovery_chunk(output, initial_bytes, tail, signature, written, max_bytes)
            recovered_data.extend(initial_bytes[: written])

            while written < max_bytes and not footer_found:
                wanted = min(64 * 1024, max_bytes - written)
                chunk = source.read(wanted)
                if not chunk:
                    break

                extra_stream_bytes_read += len(chunk)
                just_written, footer_found, chunk_bytes_consumed = write_recovery_chunk(output, chunk, tail, signature, written, max_bytes)
                recovered_data.extend(chunk[: just_written - written])
                written = just_written
                if footer_found and chunk_bytes_consumed < len(chunk):
                    unread_tail = len(chunk) - chunk_bytes_consumed
                    source.seek(-unread_tail, os.SEEK_CUR)
                    extra_stream_bytes_read -= unread_tail

        validation_score = 0.0
        validation_reason = "No validator"
        validator = get_validator_for_signature(signature)
        if validator is not None:
            validation = validator.validate(bytes(recovered_data))
            validation_score = validation.score
            validation_reason = validation.reason

        return RecoveryResult(
            path,
            written,
            estimate_confidence(signature, footer_found, written, max_bytes),
            extra_stream_bytes_read,
            initial_bytes_consumed,
            signature.name,
            validation_score,
            validation_reason,
        )


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
        f"bytes={result.bytes_written} "
        f"validation={result.validation_score:.2f} "
        f"reason={result.validation_reason}"
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
