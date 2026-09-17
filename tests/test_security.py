"""Public workspace and conservative-retention tests without network access."""

import os
import tempfile
import time
import unittest
from pathlib import Path

from app import create_app
from gambletrace.services.retention import cleanup_generated_files


class SecurityTests(unittest.TestCase):
    def test_case_workspace_is_public_and_login_route_is_not_exposed(self):
        root_dir = os.environ.get("GAMBLETRACE_TEST_TEMP_DIR") or None
        with tempfile.TemporaryDirectory(dir=root_dir) as temporary_directory:
            root = Path(temporary_directory)
            app = create_app({
                "TESTING": True,
                "SECRET_KEY": "test-secret-key",
                "DATABASE_PATH": str(root / "test.db"),
                "CASE_STORAGE_DIR": str(root / "case-storage"),
                "TEMP_DIR": str(root / "temp"),
            })
            client = app.test_client()
            self.assertEqual(client.get("/cases").status_code, 200)
            self.assertEqual(client.get("/auth/login").status_code, 404)
            with client.session_transaction() as browser_session:
                token = browser_session["csrf_token"]
            self.assertEqual(client.post("/cases/new", data={
                "csrf_token": token,
            }).status_code, 400)
            missing_csrf = client.post("/cases/new", data={})
            self.assertEqual(missing_csrf.status_code, 400)

    def test_retention_only_targets_exports_and_temp_files(self):
        root_dir = os.environ.get("GAMBLETRACE_TEST_TEMP_DIR") or None
        with tempfile.TemporaryDirectory(dir=root_dir) as temporary_directory:
            root = Path(temporary_directory)
            case_root, temp_root = root / "cases", root / "temp"
            evidence = case_root / "case-1" / "evidence" / "observation" / "immutable.txt"
            export = case_root / "case-1" / "exports" / "old.csv"
            temporary = temp_root / "old.csv"
            for path in (evidence, export, temporary):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("test", encoding="utf-8")
                old_time = time.time() - 10 * 86400
                os.utime(path, (old_time, old_time))
            preview = cleanup_generated_files(
                case_storage_dir=str(case_root), temp_dir=str(temp_root),
                export_retention_days=1, temp_retention_days=1,
            )
            self.assertEqual(preview["candidates"], 2)
            cleanup_generated_files(
                case_storage_dir=str(case_root), temp_dir=str(temp_root),
                export_retention_days=1, temp_retention_days=1, apply=True,
            )
            self.assertTrue(evidence.exists())
            self.assertFalse(export.exists())
            self.assertFalse(temporary.exists())


if __name__ == "__main__":
    unittest.main()
