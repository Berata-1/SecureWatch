import hashlib


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(8192):
                sha256.update(chunk)

        return sha256.hexdigest()

    except (PermissionError, FileNotFoundError. OSError):
        return None