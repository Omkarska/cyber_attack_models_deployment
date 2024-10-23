import requests
import time

# Function to upload a file to VirusTotal and get the scan ID
def upload_file_to_virustotal(file_path, api_key):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": api_key
    }

    # Open the binary file in read-binary mode
    with open(file_path, "rb") as file:
        files = {"file": file}
        response = requests.post(url, headers=headers, files=files)

    # Check if the upload was successful and return the scan ID
    if response.status_code == 200:
        scan_data = response.json()
        scan_id = scan_data["data"]["id"]
        return scan_id
    else:
        print(f"Upload failed. Status code: {response.status_code}")
        return None

# Function to fetch scan results using scan ID
def fetch_scan_results(scan_id, api_key):
    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {"x-apikey": api_key}

    # Poll the API until the scan is completed
    while True:
        response = requests.get(url, headers=headers)
        result = response.json()

        if response.status_code == 200:
            status = result["data"]["attributes"]["status"]
            if status == "completed":
                return result["data"]["attributes"]["results"]
            else:
                print("Scan in progress... Retrying in 5 seconds.")
                time.sleep(5)
        else:
            print(f"Failed to fetch results. Status code: {response.status_code}")
            break

    return None

# Function to summarize the scan results
def summarize_results(results):
    total_engines = len(results)
    malicious_count = 0

    # Iterate over all engine results
    for engine, result in results.items():
        category = result['category']
        detection_result = result['result']

        # Check if any engine flagged the file as malicious
        if category == 'malicious':
            malicious_count += 1

    # Determine final prediction
    if malicious_count > 0:
        return "Malicious File", malicious_count / total_engines
    else:
        return "Clean File", 1 - (malicious_count / total_engines)
