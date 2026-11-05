"""JSON and exact-text callers share publication without changing wire bytes."""
from pathlib import Path
import tempfile
import unittest

from heptabao.transport import BaoError, private_write, private_write_text


class PrivateTextPublicationTests(unittest.TestCase):
    def test_json_string_stays_json_and_text_keeps_exact_newlines(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = "first\nsecond\n\n"
            private_write(root / "json", text)
            private_write_text(root / "text", text)
            self.assertEqual((root / "json").read_bytes(), b'"first\\nsecond\\n\\n"\n')
            self.assertEqual((root / "text").read_bytes(), text.encode())
            private_write_text(root / "text", "")
            self.assertEqual((root / "text").read_bytes(), b"")

    def test_create_only_refuses_existing_without_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "text"
            private_write_text(path, "fixture-before", replace=False)
            with self.assertRaisesRegex(BaoError, "output_already_exists"):
                private_write_text(path, "fixture-after", replace=False)
            self.assertEqual(path.read_text(), "fixture-before")
            self.assertEqual(list(Path(directory).glob(".bao-write-*")), [])

    def test_wrong_type_is_rejected_without_io(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "text"
            for value in (None, b"fixture", {"fixture": 1}, 7):
                with self.subTest(kind=type(value).__name__):
                    with self.assertRaisesRegex(BaoError, "^private_text_requires_string$"):
                        private_write_text(path, value)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_invalid_utf8_has_fixed_error_and_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "text"
            with self.assertRaisesRegex(BaoError, "^private_text_requires_utf8$"):
                private_write_text(path, "fixture-\ud800")
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
