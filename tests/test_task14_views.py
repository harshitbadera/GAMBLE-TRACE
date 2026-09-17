"""Smoke tests for the task 14 investigation workspace read views."""

import os
import json
import tempfile
import unittest
import uuid
from pathlib import Path

from app import create_app
from gambletrace.persistence import get_database
from gambletrace.services.case_management import add_seed_domains, create_case


class InvestigationViewTests(unittest.TestCase):
    def test_investigation_views_render_for_a_case(self):
        test_root = os.environ.get("GAMBLETRACE_TEST_TEMP_DIR") or None
        with tempfile.TemporaryDirectory(dir=test_root) as temporary_directory:
            root = Path(temporary_directory)
            app = create_app({
            "TESTING": True,
            "AUTH_ENABLED": False,
                "DATABASE_PATH": str(root / "test.db"),
                "CASE_STORAGE_DIR": str(root / "case-storage"),
                "TEMP_DIR": str(root / "temp"),
            })
            with app.app_context():
                database = get_database()
                case = create_case(database, "Task 14 workspace smoke test")
                add_seed_domains(
                    database, case["id"], {"alpha-test.example", "beta-test.example"}
                )
                with database.connect() as connection:
                    domain_ids = [
                        row["id"] for row in connection.execute(
                            "SELECT id FROM case_domains WHERE case_id = ?", (case["id"],)
                        )
                    ]
                    cluster_id = str(uuid.uuid4())
                    connection.execute(
                        """
                        INSERT INTO clusters (id, case_id, cluster_key, name, confidence, summary)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (cluster_id, case["id"], "smoke", "Smoke cluster", "MEDIUM", "Synthetic test cluster"),
                    )
                    for domain_id in domain_ids:
                        connection.execute(
                            """
                            INSERT INTO cluster_members (id, cluster_id, entity_type, entity_id, confidence)
                            VALUES (?, ?, 'CASE_DOMAIN', ?, 'MEDIUM')
                            """,
                            (str(uuid.uuid4()), cluster_id, domain_id),
                        )
                    connection.execute(
                        """
                        INSERT INTO relationships (
                            id, case_id, source_type, source_id, relationship_type,
                            target_type, target_id, confidence, explanation
                        ) VALUES (?, ?, 'CASE_DOMAIN', ?, 'CORRELATED_INFRASTRUCTURE',
                                  'CASE_DOMAIN', ?, 'HIGH', ?)
                        """,
                        (
                            str(uuid.uuid4()), case["id"], domain_ids[0], domain_ids[1],
                            json.dumps({
                                "score": 70,
                                "signals": ["SHARED_CERTIFICATE"],
                                "factors": [{
                                    "code": "SHARED_CERTIFICATE",
                                    "label": "Shared Certificate",
                                    "points": 25,
                                    "detail": "Synthetic graph edge",
                                }],
                            }),
                        ),
                    )

                client = app.test_client()
                urls = [
                    "/cases",
                    f"/cases/{case['id']}",
                    f"/cases/{case['id']}/domains/{domain_ids[0]}",
                    f"/cases/{case['id']}/evidence",
                    f"/cases/{case['id']}/timeline",
                    f"/cases/{case['id']}/alerts",
                    f"/cases/{case['id']}/clusters/{cluster_id}",
                    f"/cases/{case['id']}/graph",
                ]
                for url in urls:
                    response = client.get(url)
                    self.assertEqual(response.status_code, 200, url)
                self.assertIn(b"SHARED_CERTIFICATE", client.get(urls[-1]).data)


if __name__ == "__main__":
    unittest.main()
