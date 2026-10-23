import binascii
import hashlib
import io
import os
import tempfile
import threading
import time

import psutil
import recovery_mvp
from pathlib import Path
from recovery_mvp import SignatureScanner, FileSignature


class CountingFile:
    def __init__(self, file_obj):
        self._file = file_obj
        self.bytes_read = 0

    def read(self, size=-1):
        data = self._file.read(size)
        self.bytes_read += len(data) if data else 0
        return data

    def seek(self, offset, whence=os.SEEK_SET):
        return self._file.seek(offset, whence)

    def tell(self):
        return self._file.tell()

    def close(self):
        return self._file.close()

    def __getattr__(self, name):
        return getattr(self._file, name)


def build_jpeg_candidate():
    return (
        b"\xff\xd8"
        b"\xff\xe0\x00\x10JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xdb\x00\x04\x00\x08\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xff\xd9"
    )


def build_png_candidate():
    chunks = [
        b"\x89PNG\r\n\x1a\n",
        b"\x00\x00\x00\x0dIHDR" + b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00",
    ]
    crc = binascii.crc32(chunks[-1][4:]) & 0xFFFFFFFF
    chunks.append(crc.to_bytes(4, "big"))
    chunks.append(b"\x00\x00\x00\x00IEND")
    crc = binascii.crc32(b"IEND") & 0xFFFFFFFF
    chunks.append(crc.to_bytes(4, "big"))
    return b"".join(chunks)


def build_pdf_candidate():
    return b"%PDF-1.0\n1 0 obj\n<<>>\nendobj\nstartxref\n9\n%%EOF"


def build_zip_candidate():
    local = b"PK\x03\x04" + b"\x14\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"hello"
    cd = b"PK\x01\x02" + b"\x14\x00" + b"\x14\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"hello"
    cd_size = len(cd)
    cd_offset = len(local)
    eocd = (
        b"PK\x05\x06"
        + (0).to_bytes(2, "little")
        + (0).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
        + (1).to_bytes(2, "little")
        + cd_size.to_bytes(4, "little")
        + cd_offset.to_bytes(4, "little")
        + (0).to_bytes(2, "little")
    )
    return local + cd + eocd


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            data = f.read(8192)
            if not data:
                break
            h.update(data)
    return h.hexdigest()


def main():
    process = psutil.Process()
    peak_rss = 0
    stop_flag = threading.Event()

    def monitor():
        nonlocal peak_rss
        while not stop_flag.is_set():
            try:
                rss = process.memory_info().rss
                peak_rss = max(peak_rss, rss)
            except psutil.Error:
                pass
            time.sleep(0.05)

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        source_path = td / "baseline_input.bin"
        output_dir = td / "output"
        output_dir.mkdir()

        payload = b"A" * (2 * 1024 * 1024)
        chunks = [
            b"PRE",
            build_jpeg_candidate(),
            payload,
            build_png_candidate(),
            payload,
            build_pdf_candidate(),
            payload,
            build_zip_candidate(),
            payload,
        ]
        with source_path.open("wb") as f:
            for chunk in chunks:
                f.write(chunk)

        signatures = recovery_mvp.SIGNATURES
        scanner = SignatureScanner(signatures)

        with source_path.open("rb") as source_file:
            counting_file = CountingFile(source_file)
            monitor_thread = threading.Thread(target=monitor, daemon=True)
            monitor_thread.start()
            start = time.perf_counter()
            recovered = scanner.scan(counting_file, output_dir, max_bytes_per_file=16 * 1024 * 1024, max_candidates=0, min_bytes=0)
            elapsed = time.perf_counter() - start
            stop_flag.set()
            monitor_thread.join()

        recovered_files = sorted(output_dir.iterdir())
        hashes = {p.name: sha256_of_file(p) for p in recovered_files}

        print("Baseline measurement")
        print(f"input_size={source_path.stat().st_size}")
        print(f"bytes_scanned={counting_file.bytes_read}")
        print(f"candidates_found={recovered}")
        print(f"bytes_recovered={sum(p.stat().st_size for p in recovered_files)}")
        print(f"output_hashes={hashes}")
        print(f"wall_time_s={elapsed:.3f}")
        print(f"peak_rss_bytes={peak_rss}")


if __name__ == "__main__":
    main()
