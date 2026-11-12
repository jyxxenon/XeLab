"""Run the object storage suite through the existing Kernel M1 discovery."""

from pathlib import Path
import unittest


def load_tests(_loader, _tests, _pattern):
    suite = Path(__file__).resolve().parents[2] / "examples" / "object-storage"
    # Older unittest releases keep the new root on the loader after discovery.
    # Use a separate loader so the host suite can keep scanning its own directory.
    return unittest.TestLoader().discover(
        str(suite), pattern="test_store.py", top_level_dir=str(suite),
    )
