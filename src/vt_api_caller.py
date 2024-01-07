import requests
import json
import os
import time
from json2html import json2html


def vt_upload(file_name):
    # 1.  API details
    url = "https://www.virustotal.com/api/v3/files"

    # 2.  Construct the full path to the file in the 'in/files/' directory
    file_path = os.path.join("in", "files", file_name)

    # 3.  Check if the file exists
    if not os.path.isfile(file_path):
        print(f"File '{file_name}' not found in 'in/files/' directory.")
        return

    # 4.  Prepare the file for upload
    files = {"file": (file_name, open(file_path, "rb"), "application/x-msdos-program")}
    headers = {
        "accept": "application/json",
        "x-apikey": "67e5c3c24a1b0c29c3b586c139a62e60a1effdd82515dcee9feff6fa53a5bdbe",
    }

    response = requests.post(url, files=files, headers=headers)

    if response.status_code == 200:
        print(f"'{file_name}' has been uploaded to VirusTotal at URL {url}")
    else:
        print(
            f"Failed to upload '{file_name}' to VirusTotal. Status code: {response.status_code}"
        )


def vt_request(file_hash):
    # 1.  API details
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": "67e5c3c24a1b0c29c3b586c139a62e60a1effdd82515dcee9feff6fa53a5bdbe",
    }

    # 2.  Make the request
    response = requests.get(url, headers=headers)

    # 3.  Convert the response to JSON format
    response_json = response.json()

    # 4.  Get the current timestamp
    timestamp = time.strftime("Date:%Y-%m-%d Time:%H-%M-%S")

    # 5.  Create the directory path for JSON and HTML reports
    dir_path = os.path.join("out/reports/json", timestamp)
    html_dir_path = os.path.join("out/reports/html", timestamp)

    # 6.  Create the directories if they don't exist
    os.makedirs(dir_path, exist_ok=True)
    os.makedirs(html_dir_path, exist_ok=True)

    # 7.  File path for the JSON and HTML files
    json_file_path = os.path.join(dir_path, f"{file_hash}.json")
    html_file_path = os.path.join(html_dir_path, f"{file_hash}.html")

    # 8.  Save the response to a JSON file
    with open(json_file_path, "w") as json_file:
        json.dump(response_json, json_file, indent=4)

    # 9.  Convert JSON to HTML and save to an HTML file
    html_content = json2html.convert(json=response_json)
    with open(html_file_path, "w") as html_file:
        html_file.write(html_content)

    print(f"Response saved to '{json_file_path}'")
    print(f"HTML report generated at '{html_file_path}'")
