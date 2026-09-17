"""Liveness report service boundary."""

from screenshot_manager import run_liveness_and_generate_report


def generate_liveness_report(domains: list[str], output_filename: str) -> str:
    """Generate the current DOCX liveness report for a set of domains."""
    return run_liveness_and_generate_report(domains, output_filename)
