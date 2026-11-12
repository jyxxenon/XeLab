"""Run the object storage suite through the existing Kernel M1 discovery."""

from pathlib import Path


def load_tests(loader, _tests, _pattern):
    suite = Path(__file__).resolve().parents[2] / "examples" / "object-storage"
    return loader.discover(str(suite), pattern="test_store.py", top_level_dir=str(suite))
