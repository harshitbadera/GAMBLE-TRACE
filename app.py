"""Compatibility entry point for the GambleTrace Flask application.

Run this file with ``python app.py`` during local development. Application
setup and HTTP routes live in the ``gambletrace`` package.
"""

from gambletrace import create_app


app = create_app()


if __name__ == "__main__":
    print()
    print("=" * 58)
    print("  GAMBLETRACE — Threat Intelligence Dashboard")
    print("  Open: http://localhost:5000")
    print("=" * 58)
    print("  Screenshots require: python -m playwright install chromium")
    print("=" * 58)
    print()
    app.run(debug=True, host="0.0.0.0", port=5000)
