"""Synthetic tests for report, IOC, graph, and verified evidence exports."""

import hashlib
import os
import tempfile
import unittest
import uuid
from pathlib import Path
import zipfile

from app import create_app
from gambletrace.persistence import get_database
from gambletrace.services.case_exports import (
    generate_case_report,
    generate_evidence_zip,
    generate_graph_export,
    generate_ioc_export,
)
from gambletrace.services.case_management import add_seed_domains, create_case
from gambletrace.services.observations import record_domain_observation


class CaseExportTests(unittest.TestCase):
    def test_case_exports_include_retained_case_data_and_verified_artifact(self):
        root_dir = os.environ.get("GAMBLETRACE_TEST_TEMP_DIR") or None
        with tempfile.TemporaryDirectory(dir=root_dir) as temporary_directory:
            root = Path(temporary_directory)
            storage = root / "case-storage"
            app = create_app({
                "TESTING": True,
                "AUTH_ENABLED": False,
                "DATABASE_PATH": str(root / "test.db"),
                "CASE_STORAGE_DIR": str(storage),
                "TEMP_DIR": str(root / "temp"),
            })
            with app.app_context():
                database = get_database()
                case = create_case(database, "Export smoke test")
                add_seed_domains(database, case["id"], {"export-test.example"})
                with database.connect() as connection:
                    domain_id = connection.execute(
                        "SELECT id FROM case_domains WHERE case_id = ?", (case["id"],)
                    ).fetchone()["id"]
                observation = record_domain_observation(
                    database, case["id"], domain_id, "SUCCESS", "ACTIVE",
                    final_url="https://export-test.example/landing",
                )
                relative_path = f"{case['id']}/observations/{observation['id']}/sample.txt"
                artifact_path = storage / relative_path
                artifact_path.parent.mkdir(parents=True, exist_ok=True)
                artifact_path.write_bytes(b"synthetic evidence")
                digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
                with database.connect() as connection:
                    connection.execute(
                        """
                        INSERT INTO evidence_artifacts (
                            id, observation_id, artifact_type, stored_path, sha256, size_bytes, mime_type, source_url
                        ) VALUES (?, ?, 'HTML_SNAPSHOT', ?, ?, ?, 'text/plain', '')
                        """,
                        (str(uuid.uuid4()), observation["id"], relative_path, digest, artifact_path.stat().st_size),
                    )

                report = generate_case_report(database, case["id"], str(storage))
                iocs = generate_ioc_export(database, case["id"], str(storage), "csv")
                graph = generate_graph_export(database, case["id"], str(storage), "graphml")
                package = generate_evidence_zip(database, case["id"], str(storage))

                self.assertIn(case["case_number"], report.read_text(encoding="utf-8"))
                self.assertIn("export-test.example", iocs.read_text(encoding="utf-8"))
                self.assertIn("<graphml", graph.read_text(encoding="utf-8"))
                with zipfile.ZipFile(package) as archive:
                    self.assertIn(f"evidence/{relative_path}", archive.namelist())
                    verification = archive.read("evidence_verification.json").decode("utf-8")
                    self.assertIn('"verification": "MATCH"', verification)

                client = app.test_client()
                self.assertEqual(client.get(f"/cases/{case['id']}/exports").status_code, 200)
                response = client.get(f"/cases/{case['id']}/exports/iocs/json")
                self.assertEqual(response.status_code, 200)
                response.close()


if __name__ == "__main__":
    unittest.main()
