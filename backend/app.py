from flask import Flask, request, jsonify
from pymongo import MongoClient
import requests
import asyncio
import time
import os

# Initialize Flask app
app = Flask(__name__)

# API Keys & Base URLs
NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VULDB_API_KEY = os.getenv("VULDB_API_KEY")

# MongoDB Configuration
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["ThreatMesh"]
collected_data_collection = db["collected_data"]
nvd_collection = db["nvdcve-1.1"]  # Adjust collection name if needed

async def initialize_db():
    """Initialize MongoDB connection."""
    print("✅ MongoDB initialized successfully!")

def poll_endpoint(ip_address):
    """Poll endpoint PC to collect system data."""
    try:
        url = f"http://{ip_address}:6612/"
        response = requests.post(url, json={"command": "SCAN"}, timeout=10)
        response.raise_for_status()
        return response.json().get("data", {})
    except requests.exceptions.RequestException as e:
        print(f"Error polling {ip_address}: {e}")
        return {"error": str(e)}

def extract_os_info(os_version):
    """Extract OS details from the os_version string."""
    try:
        parts = os_version.split(" ")
        os_name = parts[0] + " " + parts[1]  # Example: "Windows 11"
        version = next((p for p in parts if "H" in p), "")  # Example: "23H2"
        return os_name.strip(), version.strip()
    except Exception as e:
        print(f"Error extracting OS details: {e}")
        return os_version, ""

def clean_and_format_query(text):
    """Clean and format a query string for keyword search."""
    if not isinstance(text, str):
        return ""  # Ignore non-string input
    
    text = text.strip().replace("(", "").replace(")", "").replace("-", "").replace(",", "")
    text = ''.join(e for e in text if e.isalnum() or e.isspace())
    keywords = text.split()[:2]
    return " ".join(keywords)

def save_collected_data(data, ip_address):
    """Save collected data to MongoDB."""
    document = {
        "ip_address": ip_address,
        "os_version": data.get("os_version", "Unknown"),
        "system_stats": data.get("system_stats", {}),
        "open_ports": data.get("open_ports", {}),
        "installed_apps": data.get("installed_apps", []),
        "firewall_state": data.get("firewall_state", {}),
        "antivirus_status": data.get("antivirus_status", {}),
        "smb_status": data.get("smb_status", {}),
        "vulnerabilities": [],
    }
    collected_data_collection.update_one({"ip_address": ip_address}, {"$set": document}, upsert=True)
    print(f"✅ Data saved successfully for IP: {ip_address}")

def fetch_cves_from_local_db(query):
    """Fetch CVEs from the local MongoDB NVD collection based on multiple criteria."""
    # Search in multiple fields: CVE ID, description, and CPE entries
    results = nvd_collection.find({
        "$or": [
            {"cve.CVE_data_meta.ID": {"$regex": query, "$options": "i"}},
            {"cve.description.description_data.value": {"$regex": query, "$options": "i"}},
            {"configurations.nodes.cpe_match.cpe23Uri": {"$regex": query, "$options": "i"}}
        ]
    })

    # Format results for output
    return [
        {
            "source": "Local NVD",
            "cve": vuln["cve"]["CVE_data_meta"]["ID"],
            "description": vuln["cve"]["description"]["description_data"][0]["value"],
            "published_date": vuln.get("publishedDate", "N/A")
        }
        for vuln in results
    ]

def process_cves_for_collected_data():
    """Process CVEs for collected data stored in MongoDB."""
    records = list(collected_data_collection.find({}))
    print(f"Found {len(records)} records to process.")

    for record in records:
        ip_address = record.get("ip_address", "Unknown")
        os_version = record.get("os_version", "Unknown")
        installed_apps = record.get("installed_apps", [])
        running_processes = record.get("system_stats", {}).get("running_processes", [])
        open_ports = record.get("open_ports", {}).get("Tcp", []) + record.get("open_ports", {}).get("Udp", [])
        antivirus_status = record.get("antivirus_status", {})
        smb_status = record.get("smb_status", {})

        print(f"Processing record for IP: {ip_address}")

        # Ensure all required arguments are passed to fetch_cve_data()
        vulnerabilities = fetch_cve_data(
            os_version,
            installed_apps,
            running_processes,
            open_ports,
            antivirus_status,
            smb_status
        )
        
        # Update the document with the found vulnerabilities
        collected_data_collection.update_one({"_id": record["_id"]}, {"$set": {"vulnerabilities": vulnerabilities}})
    
    print("CVE processing completed.")

def fetch_cve_data(os_version, installed_apps, running_processes, open_ports, antivirus_status, smb_status):
    """Fetch CVEs by only searching the local MongoDB database."""
    print("Fetching CVEs locally for:", os_version, installed_apps, running_processes, open_ports, antivirus_status, smb_status)
    
    cves = []

    # --- Step 1: Generate queries for each relevant attribute ---
    queries = [
        clean_and_format_query(os_version.get('OS', '')) if isinstance(os_version, dict) else clean_and_format_query(os_version),
        *[clean_and_format_query(app.get("name", "")) for app in installed_apps],
        *[clean_and_format_query(proc.get("name", "")) for proc in running_processes],
        *[clean_and_format_query(port.get("process", "")) for port in open_ports]
    ]

    # --- Step 2: Search the local MongoDB for each query ---
    for query in queries:
        if query:
            print(f"Searching for CVEs with query: {query}")
            local_cves = fetch_cves_from_local_db(query)
            cves.extend(local_cves)

    print(f"Total CVEs found locally: {len(cves)}")
    return cves

def fetch_cves_from_nvd(os_version, installed_apps, running_processes, open_ports):
    """Fetch CVEs from NVD API v2."""
    cves = []

    def query_nvd(params):
        try:
            response = requests.get(NVD_BASE_URL, params=params, timeout=10)
            response.raise_for_status()
            return response.json().get("vulnerabilities", [])
        except requests.RequestException as e:
            print(f"⚠️ Request error: {e}")
            return []

    queries = [clean_and_format_query(os_version)]
    for keyword in queries:
        if keyword:
            params = {"keywordSearch": keyword, "resultsPerPage": 5, "apiKey": NVD_API_KEY}
            cves.extend(query_nvd(params))
            time.sleep(1)

    return [{"source": "NVD", "cve": cve["cve"]["id"], "description": cve["cve"]["descriptions"][0]["value"]}
            for cve in cves]

def fetch_cves_from_vuldb(os_version, installed_apps, running_processes, open_ports):
    """Fetch CVEs from VulDB API."""
    base_url = "https://vuldb.com/?api"
    headers = {"Authorization": f"Bearer {VULDB_API_KEY}"}
    cves = []

    def query_vuldb(query):
        try:
            response = requests.get(base_url, headers=headers, params={"search": query}, timeout=10)
            response.raise_for_status()
            return response.json().get("result", [])
        except requests.RequestException as e:
            print(f"⚠️ Error fetching CVE data from VulDB: {e}")
            return []

    queries = [os_version]
    for keyword in queries:
        if keyword:
            cves.extend(query_vuldb(keyword))
            time.sleep(1)

    return [{"source": "VulDB", "cve": cve["entry"]["id"], "description": cve["entry"]["summary"]}
            for cve in cves]

@app.route("/scans/cves-only", methods=["POST"])
def search_cves_only():
    process_cves_for_collected_data()
    return jsonify({"message": "CVE search completed using existing data"}), 200

@app.route("/scans/start", methods=["POST"])
def start_scan():
    try:
        data = request.json
        mode = data.get("mode", "full")
        if mode == "cves-only":
            process_cves_for_collected_data()
            return jsonify({"message": "CVE search completed using existing data"}), 200

        ip_segment = data.get("ip_segment")
        if not ip_segment:
            return jsonify({"error": "Missing 'ip_segment'"}), 400

        ip_list = ip_segment.split(",")
        scan_results = []

        for ip in ip_list:
            ip = ip.strip()
            collected_data = poll_endpoint(ip)

            if isinstance(collected_data, dict) and "error" not in collected_data:
                save_collected_data(collected_data, ip)
                scan_results.append({"ip": ip, "status": "Data collected successfully"})
            else:
                scan_results.append({"ip": ip, "status": collected_data.get("error", "Unknown error")})

        process_cves_for_collected_data()
        return jsonify({"message": "Scan and CVE search completed", "results": scan_results}), 200

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route("/")
def home():
    return "ThreatMesh Backend is Running!"

if __name__ == "__main__":
    import hypercorn.asyncio
    from hypercorn.config import Config

    async def main():
        await initialize_db()
        config = Config()
        config.bind = ["127.0.0.1:5000"]
        await hypercorn.asyncio.serve(app, config)

    asyncio.run(main())
