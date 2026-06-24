import collections
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recovery_mvp import (
    FileSignature,
    estimate_confidence,
    select_signatures,
    scan_source,
    write_recovery_chunk,
)


class RecoveryMvpTest(unittest.TestCase):
    def test_select_signatures_all(self):
        signatures = select_signatures("all")
        self.assertGreaterEqual(len(signatures), 1)

    def test_select_signatures_subset(self):
        signatures = select_signatures("jpeg,png")
        self.assertEqual({sig.name for sig in signatures}, {"jpeg", "png"})

    def test_write_recovery_chunk_footer_found_across_chunks(self):
        signature = FileSignature("test", ".bin", b"HEAD", b"FOOT", 1024)
        tail = collections.deque(maxlen=len(signature.footer))

        output = io.BytesIO()
        total_written, footer_found, bytes_written = write_recovery_chunk(
            output,
            b"DATAFO",
            tail=tail,
            signature=signature,
            already_written=0,
            max_bytes=1024,
        )
        self.assertFalse(footer_found)
        self.assertEqual(total_written, 6)
        self.assertEqual(bytes_written, 6)
        self.assertEqual(output.getvalue(), b"DATAFO")

        output = io.BytesIO()
        total_written, footer_found, bytes_written = write_recovery_chunk(
            output,
            b"OTEND",
            tail=tail,
            signature=signature,
            already_written=6,
            max_bytes=1024,
        )
        self.assertTrue(footer_found)
        self.assertEqual(total_written, 8)
        self.assertEqual(bytes_written, 2)
        self.assertEqual(output.getvalue(), b"OT")

    def test_scan_source_recovers_jpeg(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            source_path = temp_dir / "sample.bin"
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            source_path.write_bytes(b"PRE\xff\xd8\xffFILE\xff\xd9POST")

            with patch("builtins.print"):
                result = scan_source(
                    str(source_path),
                    output_dir,
                    max_bytes_per_file=1024 * 1024,
                    max_candidates=0,
                    signatures=select_signatures("jpeg"),
                    min_bytes=0,
                )

            self.assertEqual(result, 0)
            recovered_files = list(output_dir.iterdir())
            self.assertEqual(len(recovered_files), 1)
            self.assertTrue(recovered_files[0].name.endswith(".jpg"))

    def test_estimate_confidence_with_footer(self):
        self.assertEqual(estimate_confidence(FileSignature("jpeg", ".jpg", b"", b"", 0), True, 100, 1024), 85)
        self.assertEqual(estimate_confidence(FileSignature("zip-office", ".zip", b"", b"", 0), True, 100, 1024), 70)


if __name__ == "__main__":
    unittest.main()
