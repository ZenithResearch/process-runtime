"""Regressions for independently found false-equivalence in restore evidence."""
from contextlib import closing
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("runtime_backup_drill", ROOT / "scripts/verify_backup_restore.py")
drill = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drill)


class BackupRestoreEvidenceTests(unittest.TestCase):
    def snapshot(self, root, name, value):
        path = root / name
        with closing(sqlite3.connect(path)) as database:
            database.execute("CREATE TABLE fixture (value)")
            database.execute("INSERT INTO fixture VALUES (?)", (value,))
            database.commit()
        return drill.logical_snapshot(path)

    def test_blob_and_its_hexadecimal_text_cannot_have_equal_fingerprints(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            blob = self.snapshot(root, "blob.db", b"\x01")
            text = self.snapshot(root, "text.db", "01")
            self.assertNotEqual(blob, text)
            self.assertNotEqual(drill.canonical(blob), drill.canonical(text))

    def test_integer_and_equal_real_remain_distinct_sqlite_values(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.assertNotEqual(self.snapshot(root, "integer.db", 1), self.snapshot(root, "real.db", 1.0))

    def test_online_backup_preserves_source_and_detects_modified_copy(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            original = self.snapshot(root, "source.db", b"\x01")
            target = root / "backup" / "runtime.db"
            self.assertEqual(drill.backup(root / "source.db", target), original)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with closing(sqlite3.connect(target)) as database:
                database.execute("UPDATE fixture SET value=?", ("01",))
                database.commit()
            self.assertNotEqual(drill.logical_snapshot(target), original)
            with self.assertRaises(FileExistsError):
                drill.backup(root / "source.db", target)


if __name__ == "__main__":
    unittest.main()
