import binascii
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import recovery_mvp
from recovery_mvp import PDFValidator, PNGValidator, ZIPValidator, select_signatures, scan_source


class MoreRecoveryTests(unittest.TestCase):
    def test_scan_recovers_png(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "p.bin"
            out = td / "out"
            out.mkdir()
            # PNG header + IEND
            src.write_bytes(b"XX\x89PNG\r\n\x1a\nDATAIEND\xaeB`\x82YY")
            with patch("builtins.print"):
                res = scan_source(str(src), out, 1024*1024, 0, select_signatures('png'), 0)
            self.assertEqual(res, 0)
            files = list(out.iterdir())
            self.assertEqual(len(files), 1)
            self.assertTrue(files[0].name.endswith('.png'))

    def test_scan_recovers_pdf(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "pdf.bin"
            out = td / "out"
            out.mkdir()
            src.write_bytes(b"HEAD%PDF-1.4\n...BODY...%%EOFTRAIL")
            with patch("builtins.print"):
                res = scan_source(str(src), out, 1024*1024, 0, select_signatures('pdf'), 0)
            self.assertEqual(res, 0)
            files = list(out.iterdir())
            self.assertEqual(len(files), 1)
            self.assertTrue(files[0].name.endswith('.pdf'))

    def test_scan_recovers_zip_office(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "zip.bin"
            out = td / "out"
            out.mkdir()
            src.write_bytes(b"XXPK\x03\x04CONTENTPK\x05\x06YY")
            with patch("builtins.print"):
                res = scan_source(str(src), out, 1024*1024, 0, select_signatures('zip-office'), 0)
            self.assertEqual(res, 0)
            files = list(out.iterdir())
            self.assertEqual(len(files), 1)
            self.assertTrue(files[0].name.endswith('.zip'))

    def test_png_validator_accepts_minimal_png(self):
        validator = PNGValidator()
        ihdr_data = b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
        ihdr_chunk = b"IHDR" + ihdr_data
        ihdr = len(ihdr_data).to_bytes(4, "big") + ihdr_chunk + binascii.crc32(ihdr_chunk).to_bytes(4, "big")
        iend_chunk = b"IEND"
        iend = (0).to_bytes(4, "big") + iend_chunk + binascii.crc32(iend_chunk).to_bytes(4, "big")
        png = b"\x89PNG\r\n\x1a\n" + ihdr + iend
        result = validator.validate(png)
        self.assertTrue(result.valid)
        self.assertGreaterEqual(result.score, 0.7)

    def test_png_validator_missing_iend(self):
        validator = PNGValidator()
        ihdr_data = b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
        ihdr_chunk = b"IHDR" + ihdr_data
        ihdr = len(ihdr_data).to_bytes(4, "big") + ihdr_chunk + binascii.crc32(ihdr_chunk).to_bytes(4, "big")
        png = b"\x89PNG\r\n\x1a\n" + ihdr
        result = validator.validate(png)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "Missing IEND chunk")

    def test_png_validator_truncated_chunk(self):
        validator = PNGValidator()
        png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00"
        result = validator.validate(png)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "Invalid PNG chunk structure")

    def test_png_validator_bad_crc(self):
        validator = PNGValidator()
        ihdr_data = b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
        ihdr_chunk = b"IHDR" + ihdr_data
        ihdr = len(ihdr_data).to_bytes(4, "big") + ihdr_chunk + (0).to_bytes(4, "big")
        iend_chunk = b"IEND"
        iend = (0).to_bytes(4, "big") + iend_chunk + binascii.crc32(iend_chunk).to_bytes(4, "big")
        png = b"\x89PNG\r\n\x1a\n" + ihdr + iend
        result = validator.validate(png)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "Invalid PNG chunk structure")

    @patch.object(recovery_mvp, "BUFFER_SIZE", 8)
    def test_scan_recovers_png_split_header(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "pngsplit.bin"
            out = td / "out"
            out.mkdir()
            ihdr_data = b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
            ihdr_chunk = b"IHDR" + ihdr_data
            ihdr = len(ihdr_data).to_bytes(4, "big") + ihdr_chunk + binascii.crc32(ihdr_chunk).to_bytes(4, "big")
            iend_chunk = b"IEND"
            iend = (0).to_bytes(4, "big") + iend_chunk + binascii.crc32(iend_chunk).to_bytes(4, "big")
            src.write_bytes(b"\x89PNG\r\n\x1a\n" + ihdr + iend)
            with patch("builtins.print") as mock_print:
                res = scan_source(str(src), out, 1024*1024, 0, select_signatures('png'), 0)
            self.assertEqual(res, 0)
            self.assertEqual(len(list(out.iterdir())), 1)
            printed = "\n".join(str(call.args[0]) for call in mock_print.call_args_list if call.args)
            self.assertIn("validation=", printed)
            self.assertIn("reason=", printed)

    def test_pdf_validator_accepts_valid_pdf(self):
        validator = PDFValidator()
        pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n123\n%%EOF"
        result = validator.validate(pdf)
        self.assertTrue(result.valid)
        self.assertGreaterEqual(result.score, 0.7)

    def test_pdf_validator_missing_eof(self):
        validator = PDFValidator()
        pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n123\n"
        result = validator.validate(pdf)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "Missing %EOF")

    def test_pdf_validator_invalid_header(self):
        validator = PDFValidator()
        result = validator.validate(b"NOTPDF\n%%EOF")
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "Missing PDF header")

    @patch.object(recovery_mvp, "BUFFER_SIZE", 16)
    def test_scan_recovers_pdf_split_eof(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "pdfsplit.bin"
            out = td / "out"
            out.mkdir()
            pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n123\n%%EOF"
            src.write_bytes(pdf)
            with patch("builtins.print") as mock_print:
                res = scan_source(str(src), out, 1024*1024, 0, select_signatures('pdf'), 0)
            self.assertEqual(res, 0)
            self.assertEqual(len(list(out.iterdir())), 1)
            printed = "\n".join(str(call.args[0]) for call in mock_print.call_args_list if call.args)
            self.assertIn("validation=", printed)
            self.assertIn("reason=", printed)

    def test_zip_validator_accepts_valid_zip(self):
        validator = ZIPValidator()
        local = b"PK\x03\x04" + b"A" * 26
        central_dir = b"PK\x01\x02" + b"B" * 42
        cd_offset = len(local)
        cd_size = len(central_dir)
        eocd = (
            b"PK\x05\x06"
            + (0).to_bytes(2, 'little')
            + (0).to_bytes(2, 'little')
            + (1).to_bytes(2, 'little')
            + (1).to_bytes(2, 'little')
            + cd_size.to_bytes(4, 'little')
            + cd_offset.to_bytes(4, 'little')
            + (0).to_bytes(2, 'little')
        )
        zip_data = local + central_dir + eocd
        result = validator.validate(zip_data)
        self.assertTrue(result.valid)
        self.assertGreaterEqual(result.score, 0.7)

    def test_zip_validator_missing_eocd(self):
        validator = ZIPValidator()
        result = validator.validate(b"PK\x03\x04" + b"A" * 50)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "Missing EOCD")

    def test_zip_validator_malformed_eocd(self):
        validator = ZIPValidator()
        local = b"PK\x03\x04" + b"A" * 26
        central_dir = b"PK\x01\x02" + b"B" * 42
        cd_offset = len(local)
        cd_size = len(central_dir) + 100
        eocd = (
            b"PK\x05\x06"
            + (0).to_bytes(2, 'little')
            + (0).to_bytes(2, 'little')
            + (1).to_bytes(2, 'little')
            + (1).to_bytes(2, 'little')
            + cd_size.to_bytes(4, 'little')
            + cd_offset.to_bytes(4, 'little')
            + (0).to_bytes(2, 'little')
        )
        zip_data = local + central_dir + eocd
        result = validator.validate(zip_data)
        self.assertFalse(result.valid)
        self.assertIn("has_header", result.reason)
        self.assertIn("has_eocd", result.reason)
        self.assertIn("has_central_dir", result.reason)
        self.assertNotIn("valid_eocd", result.reason)

    @patch.object(recovery_mvp, "BUFFER_SIZE", 8)
    def test_scan_recovers_zip_split_header(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "zipsplit.bin"
            out = td / "out"
            out.mkdir()
            local = b"PK\x03\x04" + b"A" * 26
            central_dir = b"PK\x01\x02" + b"B" * 42
            cd_offset = len(local)
            cd_size = len(central_dir)
            eocd = b"PK\x05\x06" + b"\x00\x00\x00\x00" + cd_size.to_bytes(4, 'little') + cd_offset.to_bytes(4, 'little') + b"\x00\x00"
            src.write_bytes(local + central_dir + eocd)
            with patch("builtins.print") as mock_print:
                res = scan_source(str(src), out, 1024*1024, 0, select_signatures('zip-office'), 0)
            self.assertEqual(res, 0)
            self.assertEqual(len(list(out.iterdir())), 1)
            printed = "\n".join(str(call.args[0]) for call in mock_print.call_args_list if call.args)
            self.assertIn("validation=", printed)
            self.assertIn("reason=", printed)


if __name__ == '__main__':
    unittest.main()
