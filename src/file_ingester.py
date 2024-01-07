import os
from md5_hash_extractor import md5_hash


def scan_filesystem(directory):
    file_hashes = []

    # 1. Add an MD5 hash known to be present in the NIST NSRL dataset for proof of concept
    file_hashes.append(("Known present NSRL test file - package_459_for_kb4345420_31bf3856ad364e35_amd64__10.0.1.2.mum","51580c2aea9de8e933c858a34502f78d",))

    # 2. Scan the filesystem and return a list of files with their MD5 hashes.
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = md5_hash(file_path)
            file_hashes.append((file, file_hash))
    return file_hashes
