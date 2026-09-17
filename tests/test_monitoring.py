"""Synthetic monitoring tests; no DNS, HTTP, or external services are used."""

import os
import tempfile
import unittest
import uuid
from pathlib import Path

from app import create_app
from gambletrace.persistence import get_database
from gambletrace.services.case_management import add_seed_domains, create_case
from gambletrace.services.monitoring import (
    evaluate_observation_changes,
    list_case_alerts,
    update_alert_status,
)
from gambletrace.services.observations import record_domain_observation


class MonitoringTests(unittest.TestCase):
    def test_dns_and_availability_changes_create_reviewable_alerts(self):
        root_dir = os.environ.get("GAMBLETRACE_TEST_TEMP_DIR") or None
        with tempfile.TemporaryDirectory(dir=root_dir) as temporary_directory:
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
                case = create_case(database, "Monitoring smoke test")
                add_seed_domains(database, case["id"], {"monitor-test.example"})
                with database.connect() as connection:
                    domain_id = connection.execute(
                        "SELECT id FROM case_domains WHERE case_id = ?", (case["id"],)
                    ).fetchone()["id"]

                def dns_writer(address):
                    def writer(connection, observation_id):
                        connection.execute(
                            """
                            INSERT INTO dns_records (id, observation_id, record_type, record_value, ttl)
                            VALUES (?, ?, 'A', ?, 60)
                            """,
                            (str(uuid.uuid4()), observation_id, address),
                        )
                    return writer

                first = record_domain_observation(
                    database, case["id"], domain_id, "SUCCESS", "ACTIVE",
                    observed_at="2026-01-01T00:00:00Z", details_writer=dns_writer("198.51.100.10"),
                )
                self.assertEqual(
                    evaluate_observation_changes(
                        database, case_id=case["id"], case_domain_id=domain_id, observation_id=first["id"]
                    ),
                    [],
                )
                second = record_domain_observation(
                    database, case["id"], domain_id, "FAILED", "OFFLINE",
                    observed_at="2026-01-02T00:00:00Z", details_writer=dns_writer("198.51.100.20"),
                )
                alerts = evaluate_observation_changes(
                    database, case_id=case["id"], case_domain_id=domain_id, observation_id=second["id"]
                )
                self.assertEqual({alert["alert_type"] for alert in alerts}, {
                    "DNS_INFRASTRUCTURE_CHANGE", "AVAILABILITY_CHANGE",
                })
                stored_alerts = list_case_alerts(database, case["id"])
                self.assertEqual(len(stored_alerts), 2)
                update_alert_status(database, case["id"], stored_alerts[0]["id"], "ACKNOWLEDGED")
                updated = next(
                    alert for alert in list_case_alerts(database, case["id"])
                    if alert["id"] == stored_alerts[0]["id"]
                )
                self.assertEqual(updated["status"], "ACKNOWLEDGED")


if __name__ == "__main__":
    unittest.main()
