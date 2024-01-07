import time
from file_ingester import scan_filesystem
from query_db import *
from vt_api_caller import *


def line_sep():
    print("=========================================")


while True:
    print("\n===== Malicious File Detection Tool =====")
    print("1. Scan from program input directory")
    print("2. Input MD5 Hash manually")
    print("3. Exit")
    line_sep()

    choice = input("Enter your choice (1-3): ")
    line_sep()

    if choice == "1":
        # Call the function to scan from program input directory
        print("Scanning from program input directory...")
        # 1. Scan the 'in' directory
        file_hashes = scan_filesystem("in")

        # 2. Display file hashes and prompt the user to submit for analysis
        for file, hash in file_hashes:
            print(f"File: {file}, Hash: {hash}")
        line_sep()
        user_input = input("Submit for analysis? (yes/no): ")
        line_sep()
        if user_input.lower() == "yes":
            # 3. Query the database and update the file list
            remaining_files = query_hashed_db(file_hashes)
            line_sep()
            print("Files remaining after benign check:")
            for file, hash in remaining_files:
                print(f"File: {file}, Hash: {hash}")
        else:
            print("Analysis cancelled.")

        line_sep()
        user_input = input("Submit to VirusTotal for analysis? (yes/no): ")
        line_sep()
        if user_input.lower() == "yes":
            # 4.  VT function call
            for file, hash in remaining_files:
                vt_upload(file)
                vt_request(hash)
                time.sleep(5)
        else:
            print("Analysis cancelled.")

    elif choice == "2":
        # 1. Prompt user to input MD5 hash manually
        md5_hash = input("Enter the MD5 hash: ")
        line_sep()
        # 2. Query the database and update the file list
        single_remaining_hash = single_query_hashed_db(md5_hash)
        line_sep()
        if single_remaining_hash == 0:
            print("File marked as benign. Analysis cancelled")
        else:
            user_input = input("Submit to VirusTotal for analysis? (yes/no): ")
            line_sep()
            if user_input.lower() == "yes":
                # 3.  VT function call
                vt_request(md5_hash)
            else:
                print("Analysis cancelled.")
    elif choice == "3":
        print("Exiting the program.")
        break
    else:
        print("Invalid choice. Please enter a number between 1 and 3.")