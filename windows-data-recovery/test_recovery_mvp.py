import collections
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import recovery_mvp
from recovery_mvp import (
    FileSignature,
    estimate_confidence,
    select_signatures,
    scan_source,
    write_recovery_chunk,
)


class RecoveryMvpTest(unittest.TestCase):
    def _scan(self, source: Path, output_dir: Path, **kwargs) -> int:
        with patch("builtins.print"):
            return scan_source(
                str(source),
                output_dir,
                max_bytes_per_file=kwargs.get("max_bytes_per_file", 1024 * 1024),
                max_candidates=kwargs.get("max_candidates", 0),
                signatures=kwargs.get("signatures", select_signatures("all")),
                min_bytes=kwargs.get("min_bytes", 0),
            )

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

            result = self._scan(source_path, output_dir, signatures=select_signatures("jpeg"))

            self.assertEqual(result, 0)
            recovered_files = list(output_dir.iterdir())
            self.assertEqual(len(recovered_files), 1)
            self.assertTrue(recovered_files[0].name.endswith(".jpg"))

    def test_empty_input_recovers_nothing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            source_path = temp_dir / "empty.bin"
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            source_path.write_bytes(b"")

            result = self._scan(source_path, output_dir, signatures=select_signatures("all"))

            self.assertEqual(result, 0)
            self.assertEqual(list(output_dir.iterdir()), [])

    def test_truncated_candidate_is_written(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            source_path = temp_dir / "truncated.bin"
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            source_path.write_bytes(b"\xff\xd8\xffSMALL")

            result = self._scan(source_path, output_dir, signatures=select_signatures("jpeg"))

            self.assertEqual(result, 0)
            recovered_files = list(output_dir.iterdir())
            self.assertEqual(len(recovered_files), 1)
            self.assertEqual(recovered_files[0].stat().st_size, 8)

    def test_random_binary_input_recovers_nothing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            source_path = temp_dir / "random.bin"
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            source_path.write_bytes(os.urandom(256))

            result = self._scan(source_path, output_dir, signatures=select_signatures("all"))

            self.assertEqual(result, 0)
            self.assertEqual(list(output_dir.iterdir()), [])

    def test_invalid_source_path_raises_file_not_found(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            missing = temp_dir / "missing.bin"

            with self.assertRaises(FileNotFoundError):
                self._scan(missing, output_dir, signatures=select_signatures("all"))

    def test_inaccessible_source_path_raises_permission_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            source_path = temp_dir / "denied.bin"
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            source_path.write_bytes(b"DATA")

            with patch("recovery_mvp.open_source_readonly", side_effect=PermissionError("Denied")):
                with self.assertRaises(PermissionError):
                    scan_source(str(source_path), output_dir, 1024 * 1024, 0, select_signatures("all"), 0)

    @patch.object(recovery_mvp, "BUFFER_SIZE", 16)
    def test_header_at_chunk_boundary_is_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            source_path = temp_dir / "boundary.bin"
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            source_path.write_bytes(b"A" * 14 + b"\xff\xd8" + b"\xffDATA\xff\xd9")

            result = self._scan(source_path, output_dir, signatures=select_signatures("jpeg"))

            self.assertEqual(result, 0)
            recovered_files = list(output_dir.iterdir())
            self.assertEqual(len(recovered_files), 1)
            self.assertTrue(recovered_files[0].name.endswith(".jpg"))

    @patch.object(recovery_mvp, "BUFFER_SIZE", 16)
    def test_header_split_across_chunk_boundary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            source_path = temp_dir / "split-header.bin"
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            source_path.write_bytes(b"A" * 15 + b"\xff" + b"\xd8\xff" + b"DATA\xff\xd9")

            result = self._scan(source_path, output_dir, signatures=select_signatures("jpeg"))

            self.assertEqual(result, 0)
            recovered_files = list(output_dir.iterdir())
            self.assertEqual(len(recovered_files), 1)
            self.assertTrue(recovered_files[0].name.endswith(".jpg"))

    @patch.object(recovery_mvp, "BUFFER_SIZE", 16)
    def test_multiple_candidates_in_same_block(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            source_path = temp_dir / "two.bin"
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            source_path.write_bytes(b"A" * 12 + b"\xff\xd8\xffA\xff\xd9\xff\xd8\xffB\xff\xd9")

            result = self._scan(source_path, output_dir, signatures=select_signatures("jpeg"))

            self.assertEqual(result, 0)
            recovered_files = sorted(list(output_dir.iterdir()))
            self.assertEqual(len(recovered_files), 2)
            self.assertTrue(recovered_files[0].name.endswith(".jpg"))
            self.assertTrue(recovered_files[1].name.endswith(".jpg"))

    @patch.object(recovery_mvp, "BUFFER_SIZE", 16)
    def test_multiple_candidates_across_boundaries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            source_path = temp_dir / "two_boundary.bin"
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            data = b"A" * 14 + b"\xff\xd8\xffA\xff\xd9" + b"B" * 2 + b"\xff\xd8\xffB\xff\xd9"
            source_path.write_bytes(data)

            result = self._scan(source_path, output_dir, signatures=select_signatures("jpeg"))

            self.assertEqual(result, 0)
            recovered_files = sorted(list(output_dir.iterdir()))
            self.assertEqual(len(recovered_files), 2)
            self.assertEqual(recovered_files[0].name, "000001_jpeg_E.jpg")
            self.assertEqual(recovered_files[1].name, "000002_jpeg_16.jpg")

    @patch.object(recovery_mvp, "BUFFER_SIZE", 12)
    def test_rejected_cross_boundary_candidate_does_not_skip_later_candidates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            source_path = temp_dir / "reject_boundary.bin"
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            source_path.write_bytes(
                b"A" * 10
                + b"\xff\xd8"
                + b"\xff" + b"X" * 12 + b"\xff\xd9"
                + b"B" * 5
                + b"\xff\xd8\xff" + b"Y" * 20 + b"\xff\xd9"
            )

            result = self._scan(source_path, output_dir, signatures=select_signatures("jpeg"), min_bytes=20)

            self.assertEqual(result, 0)
            recovered_files = sorted(list(output_dir.iterdir()))
            self.assertEqual(len(recovered_files), 1)
            self.assertEqual(recovered_files[0].name, "000001_jpeg_20.jpg")
            self.assertEqual(recovered_files[0].stat().st_size, 25)
            self.assertEqual(recovered_files[0].read_bytes(), b"\xff\xd8\xff" + b"Y" * 20 + b"\xff\xd9")

    @patch.object(recovery_mvp, "BUFFER_SIZE", 16)
    def test_footer_spanning_chunks_is_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            source_path = temp_dir / "footer_boundary.bin"
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            source_path.write_bytes(b"\xff\xd8\xff" + b"A" * 11 + b"\xff" + b"\xd9TRAIL")

            result = self._scan(source_path, output_dir, signatures=select_signatures("jpeg"))

            self.assertEqual(result, 0)
            recovered_files = list(output_dir.iterdir())
            self.assertEqual(len(recovered_files), 1)
            self.assertTrue(recovered_files[0].name.endswith(".jpg"))
            self.assertEqual(recovered_files[0].stat().st_size, 16)

    def test_max_candidates_limits_recovery_count(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            source_path = temp_dir / "two.bin"
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            source_path.write_bytes(b"\xff\xd8\xffA\xff\xd9\xff\xd8\xffB\xff\xd9")

            result = self._scan(source_path, output_dir, signatures=select_signatures("jpeg"), max_candidates=1)

            self.assertEqual(result, 0)
            recovered_files = list(output_dir.iterdir())
            self.assertEqual(len(recovered_files), 1)

    def test_min_bytes_filters_small_candidate(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            source_path = temp_dir / "small.bin"
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            source_path.write_bytes(b"\xff\xd8\xffSMALL\xff\xd9")

            result = self._scan(source_path, output_dir, signatures=select_signatures("jpeg"), min_bytes=20)

            self.assertEqual(result, 0)
            self.assertEqual(list(output_dir.iterdir()), [])

    def test_same_source_output_refused_for_source_parent_folder(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            source_path = output_dir / "same.bin"
            source_path.write_bytes(b"\xff\xd8\xffA\xff\xd9")

            result = scan_source(str(source_path), output_dir, 1024 * 1024, 0, select_signatures("jpeg"), 0)

            self.assertEqual(result, 1)
            self.assertEqual({path.name for path in output_dir.iterdir()}, {"same.bin"})

    def test_same_source_output_refused_for_source_dir_ancestor(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            source_dir = temp_dir / "source"
            source_dir.mkdir()
            output_dir = temp_dir

            self.assertTrue(recovery_mvp.output_looks_like_source(str(source_dir), output_dir))

    def test_same_source_output_refused_for_device_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            output_dir = temp_dir / "output"
            output_dir.mkdir()
            drive_letter = output_dir.resolve().drive[0]
            source = f"\\\\.\\{drive_letter}:"

            self.assertTrue(recovery_mvp.output_looks_like_source(source, output_dir))

    def test_raw_device_output_on_same_drive_is_refused(self):
        self.assertTrue(recovery_mvp.output_looks_like_source(r"\\.\\E:", Path(r"E:\recovered")))

    def test_raw_device_output_on_different_drive_is_allowed(self):
        self.assertFalse(recovery_mvp.output_looks_like_source(r"\\.\\E:", Path(r"C:\recovered")))

    def test_windows_path_case_insensitive_comparison(self):
        self.assertTrue(recovery_mvp.output_looks_like_source(r"c:/data/disk.img", Path(r"C:/data/disk.img")))

    def test_nonexistent_output_path_is_checked_safely(self):
        self.assertFalse(recovery_mvp.output_looks_like_source(r"C:/data/disk.img", Path(r"C:/recovered")))
        self.assertTrue(recovery_mvp.output_looks_like_source(r"C:/data/", Path(r"C:/data/recovered")))

    def test_estimate_confidence_with_footer(self):
        self.assertEqual(estimate_confidence(FileSignature("jpeg", ".jpg", b"", b"", 0), True, 100, 1024), 85)
        self.assertEqual(estimate_confidence(FileSignature("zip-office", ".zip", b"", b"", 0), True, 100, 1024), 70)


if __name__ == "__main__":
    unittest.main()
