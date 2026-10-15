"""Main entrypoint alias for the AirTell Streamlit Dashboard."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is on sys.path so absolute "app.…" imports resolve
# when Streamlit runs this file directly (not as ``python -m app.…``).
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from app.streamlit_app import main  # noqa: E402

if __name__ == "__main__":
    main()
