import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recovery_mvp import select_signatures, scan_source


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


if __name__ == '__main__':
    unittest.main()
