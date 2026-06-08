from pathlib import Path


def read_key_file(path: str) -> str:
    key_path = Path(path)
    if not key_path.is_absolute():
        key_path = Path.cwd() / key_path
    return key_path.read_text(encoding="utf-8")
