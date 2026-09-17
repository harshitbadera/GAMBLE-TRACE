"""Browser collection integration.

The existing Playwright implementation remains in ``screenshot_manager.py``
for CLI compatibility and is accessed here by route/service code.
"""

from screenshot_manager import run_screenshot_pipeline


async def collect_liveness_screenshots(domains: list[str]) -> list[dict]:
    """Collect liveness and screenshots using the current Playwright collector."""
    return await run_screenshot_pipeline(domains)
