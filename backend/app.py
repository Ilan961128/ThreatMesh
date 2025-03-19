import signal
import sys
import asyncio
from dataclasses import asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify
from loguru import logger
import hypercorn.asyncio
from hypercorn.config import Config
from src.nvd.mirror_nvd import setup_db
from src.collected_data import CollectedData
from src.cve_searcher.search_vulnerabilties import search_vulnerabilities
from src.mongodb import collected_data_collection, cve_collection, meta_collection
from src.poller import poll_endpoint, is_host_alive
from src.utils import is_ipaddress
from src.ip_utils import expand_ips

app = Flask(__name__)

# Setup logging
logger.remove()
logger.add(sys.stderr, level="INFO")

# Flag to detect shutdown request
shutdown_requested = False

def signal_handler(sig, frame):
    """Handles SIGINT (CTRL+C) to abort the scan gracefully."""
    global shutdown_requested
    shutdown_requested = True
    print("\n[!] Scan aborted by user.")
    sys.exit(0)

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)

def scan_ips_concurrently(ip_list):
    """
    Scans multiple IPs concurrently using ThreadPoolExecutor.
    """
    scan_results = []
    alive_ips = [ip for ip in ip_list if is_host_alive(ip)]  # Filter out dead IPs

    logger.info(f"[+] Found {len(alive_ips)}/{len(ip_list)} alive IPs. Scanning only reachable hosts.")

    if not alive_ips:
        return [{"message": "No reachable hosts found"}]

    with ThreadPoolExecutor(max_workers=10) as executor:  # Run 10 scans in parallel
        future_to_ip = {executor.submit(poll_endpoint, ip): ip for ip in alive_ips}

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            if shutdown_requested:
                break  # Stop all scans if SIGINT is received
            try:
                collected_data = future.result()
                scan_results.append({"ip": ip, "status": "Data collected successfully"})
                collected_data_collection.update_one(
                    {"ip_address": ip}, {"$set": asdict(collected_data)}, upsert=True
                )
                logger.info(f"[✓] Data saved for {ip}")
            except Exception as e:
                scan_results.append({"ip": ip, "status": f"Failed: {str(e)}"})

    return scan_results

@app.route("/poll", methods=["POST"])
def poll():
    """
    Polls PC endpoints and saves results.

    Request.body:
    {
        "ips": ["192.168.1.10", "10.0.0.1-10.0.0.5", "192.168.2.0/29"]
    }

    Returns:
        JSON response with scan results.
    """
    ip_list = request.json.get("ips")

    if not ip_list or not isinstance(ip_list, list):
        return jsonify({"error": "Invalid request format"}), 400

    expanded_ips = expand_ips(ip_list)
    if not expanded_ips:
        return jsonify({"error": "No valid IPs found"}), 400

    logger.info(f"[+] Checking reachability for {len(expanded_ips)} IPs...")
    scan_results = scan_ips_concurrently(expanded_ips)

    return jsonify({"message": "Scan completed", "results": scan_results}), 200

@app.route("/scan", methods=["GET"])
def scan():
    """
    Scan NVD mirror for vulnerabilities, using collected data collection for parameters.

    Returns:
        tuple[Response, int]: Response, http status
    """
    logger.info("Scanning Records")
    records = collected_data_collection.find({})

    for record in records:
        logger.info(f"Scanning record from IP: {record['ip_address']}")

        cd = CollectedData(**record)

        vulns = {
            "os_version": [
                cvematch.cve
                for cvematch in search_vulnerabilities(
                    cve_collection, cd.os_version.query
                )
            ],
            "installed_apps": list(
                filter(
                    lambda d: len(d["cves"]),
                    (
                        {
                            "name": installed_app.name,
                            "cves": [
                                cvematch.cve
                                for cvematch in search_vulnerabilities(
                                    cve_collection, installed_app.query
                                )
                            ],
                        }
                        for installed_app in cd.installed_apps
                    ),
                )
            ),
        }

        record["vulnerabilities"] = vulns
        collected_data_collection.update_one({"_id": record["_id"]}, {"$set": record})
    logger.info("Finished scanning")

    return jsonify({}), 200

@app.route("/install_db", methods=["GET"])
def install_db():
    """
    Install a new NVD mirror db.

    Returns:
        tuple[Response, int]: Response, http status
    """
    setup_db(cve_collection, meta_collection)
    return jsonify({"message": "Installed DB successfully"}), 200

@app.route("/")
def home():
    return "ThreatMesh Backend is Running!"

async def main():
    config = Config()
    config.bind = ["127.0.0.1:5000"]
    await hypercorn.asyncio.serve(app, config)

if __name__ == "__main__":
    asyncio.run(main())
