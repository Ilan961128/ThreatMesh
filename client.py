from http.server import BaseHTTPRequestHandler, HTTPServer
import json
DATA = {
    "os_version": {
        "OS": "Windows 11 Pro",
        "version": "23H2",
        "build": "10.0.22631.4751"
    },
    "system_stats": {
        "cpu_usage": "2.2%",
        "memory": {
            "total": "31.21 GB",
            "available": "17.63 GB",
            "used": "13.59 GB",
            "percent": "43.5%"
        },
        "disk": {
            "total": "1.82 TB",
            "used": "816.85 GB",
            "free": "1.02 TB",
            "percent": "43.9%"
        },
        "running_processes": [
            {
                "pid": 19844,
                "name": "chrome.exe",
                "cpu_percent": "16.0%",
                "memory_used": "809.17 MB"
            },
            {
                "pid": 24868,
                "name": "chrome.exe",
                "cpu_percent": "0.4%",
                "memory_used": "716.82 MB"
            },
            {
                "pid": 10496,
                "name": "Code.exe",
                "cpu_percent": "0.1%",
                "memory_used": "526.42 MB"
            },
            {
                "pid": 3964,
                "name": "Code.exe",
                "cpu_percent": "0.1%",
                "memory_used": "501.67 MB"
            },
            {
                "pid": 9424,
                "name": "Postman.exe",
                "cpu_percent": "0.1%",
                "memory_used": "385.75 MB"
            }
        ]
    },
    "open_ports": {
        "Tcp": [
            {
                "port": 7680,
                "process": "svchost.exe"
            },
            {
                "port": 49667,
                "process": "svchost.exe"
            },
            {
                "port": 5432,
                "process": "postgres.exe"
            },
            {
                "port": 49665,
                "process": "wininit.exe"
            },
            {
                "port": 3389,
                "process": "svchost.exe"
            },
            {
                "port": 445,
                "process": "System"
            },
            {
                "port": 15611,
                "process": "Postman.exe"
            },
            {
                "port": 6612,
                "process": "python.exe"
            },
            {
                "port": 28385,
                "process": "System"
            },
            {
                "port": 59869,
                "process": "logioptionsplus_agent.exe"
            },
            {
                "port": 135,
                "process": "svchost.exe"
            },
            {
                "port": 9053,
                "process": "java.exe"
            },
            {
                "port": 5432,
                "process": "postgres.exe"
            },
            {
                "port": 3389,
                "process": "svchost.exe"
            },
            {
                "port": 9052,
                "process": "java.exe"
            },
            {
                "port": 139,
                "process": "System"
            },
            {
                "port": 49664,
                "process": "lsass.exe"
            },
            {
                "port": 49350,
                "process": "esrv_svc.exe"
            },
            {
                "port": 9051,
                "process": "java.exe"
            },
            {
                "port": 5000,
                "process": "python.exe"
            },
            {
                "port": 49665,
                "process": "wininit.exe"
            },
            {
                "port": 139,
                "process": "System"
            },
            {
                "port": 9053,
                "process": "java.exe"
            },
            {
                "port": 27017,
                "process": "mongod.exe"
            },
            {
                "port": 49667,
                "process": "svchost.exe"
            },
            {
                "port": 9051,
                "process": "java.exe"
            },
            {
                "port": 15611,
                "process": "Postman.exe"
            },
            {
                "port": 49664,
                "process": "lsass.exe"
            },
            {
                "port": 28390,
                "process": "System"
            },
            {
                "port": 7680,
                "process": "svchost.exe"
            },
            {
                "port": 49668,
                "process": "spoolsv.exe"
            },
            {
                "port": 445,
                "process": "System"
            },
            {
                "port": 49666,
                "process": "svchost.exe"
            },
            {
                "port": 9100,
                "process": "lghub_updater.exe"
            },
            {
                "port": 9180,
                "process": "lghub_updater.exe"
            },
            {
                "port": 49679,
                "process": "services.exe"
            },
            {
                "port": 24830,
                "process": "AsusSoftwareManager.exe"
            },
            {
                "port": 9054,
                "process": "java.exe"
            },
            {
                "port": 27015,
                "process": "AppleMobileDeviceService.exe"
            },
            {
                "port": 135,
                "process": "svchost.exe"
            },
            {
                "port": 9054,
                "process": "java.exe"
            },
            {
                "port": 5354,
                "process": "mDNSResponder.exe"
            },
            {
                "port": 49668,
                "process": "spoolsv.exe"
            },
            {
                "port": 49666,
                "process": "svchost.exe"
            },
            {
                "port": 49351,
                "process": "esrv.exe"
            },
            {
                "port": 139,
                "process": "System"
            },
            {
                "port": 49679,
                "process": "services.exe"
            },
            {
                "port": 9052,
                "process": "java.exe"
            },
            {
                "port": 8080,
                "process": "httpd.exe"
            },
            {
                "port": 912,
                "process": "vmware-authd.exe"
            },
            {
                "port": 902,
                "process": "vmware-authd.exe"
            },
            {
                "port": 5040,
                "process": "svchost.exe"
            }
        ],
        "Udp": []
    },
    "installed_apps": [
        {
            "name": "Windows Driver Package - Apple, Inc. (USBAAPL) USB  (05/19/2017 6.0.9999.69)",
            "version": "05/19/2017 6.0.9999.69"
        },
        {
            "name": "Windows Driver Package - Apple, Inc. (USBAAPL64) USB  (05/19/2017 6.0.9999.69)",
            "version": "05/19/2017 6.0.9999.69"
        },
        {
            "name": "CrystalDiskMark 8.0.6",
            "version": "8.0.6"
        },
        {
            "name": "Docker Desktop",
            "version": "4.37.1"
        },
        {
            "name": "Git",
            "version": "2.47.0.2"
        },
        {
            "name": "Migration Toolkit 55.7.0-1",
            "version": "55.7.0-1"
        },
        {
            "name": "Notepad++ (64-bit x64)",
            "version": "8.6.9"
        },
        {
            "name": "\u05d9\u05d9\u05e9\u05d5\u05de\u05d9 Microsoft 365 \u05dc\u05d0\u05e8\u05d2\u05d5\u05e0\u05d9\u05dd - he-il",
            "version": "16.0.18324.20194"
        },
        {
            "name": "Microsoft OneDrive",
            "version": "24.244.1204.0003"
        },
        {
            "name": "PEM-HTTPD 2.4.62",
            "version": "2.4.62-1"
        },
        {
            "name": "pgAgent_PG17 4.2.2",
            "version": "4.2.2-1"
        },
        {
            "name": "PostGIS Bundle 3.5.0 for PostgreSQL x64 17 (remove only)",
            "version": "Unknown"
        },
        {
            "name": "Postgres Enterprise Manager Agent 9.8.0-1",
            "version": "9.8.0-1"
        },
        {
            "name": "PostgreSQL 17 ",
            "version": "17.2-3"
        },
        {
            "name": "psqlODBC 13.02.0000",
            "version": "13.02.0000-1"
        },
        {
            "name": "SQL-Profiler 4.1.2 - PostgreSQL 17",
            "version": "4.1.2"
        },
        {
            "name": "Ready or Not",
            "version": "Unknown"
        },
        {
            "name": "The Sims\u2122 4",
            "version": "Unknown"
        },
        {
            "name": "Forza Horizon 5",
            "version": "Unknown"
        },
        {
            "name": "Gray Zone Warfare",
            "version": "Unknown"
        },
        {
            "name": "UltraVnc",
            "version": "1.2.3.0"
        },
        {
            "name": "VLC media player",
            "version": "3.0.21"
        },
        {
            "name": "WinRAR 7.01 (64-bit)",
            "version": "7.01.0"
        },
        {
            "name": "xDB Replication Server 7.7.0",
            "version": "7.7.0-1"
        },
        {
            "name": "Wireshark",
            "version": "4.2.6.0"
        },
        {
            "name": "Java(TM) SE Development Kit 23.0.1 (64-bit)",
            "version": "23.0.1.0"
        },
        {
            "name": "iTunes",
            "version": "12.13.4.4"
        },
        {
            "name": "Logitech G HUB",
            "version": "2024.6.600476"
        },
        {
            "name": "Bonjour",
            "version": "3.1.0.1"
        },
        {
            "name": "Microsoft Visual Studio Installer",
            "version": "3.12.2149.20818"
        },
        {
            "name": "Logi Options+",
            "version": "1.86.669369"
        },
        {
            "name": "Google Chrome",
            "version": "132.0.6834.159"
        },
        {
            "name": "Node.js",
            "version": "22.11.0"
        },
        {
            "name": "Apple Mobile Device Support",
            "version": "18.0.0.32"
        },
        {
            "name": "NVIDIA Graphics Driver 566.36",
            "version": "566.36"
        },
        {
            "name": "NVIDIA app 11.0.1.184",
            "version": "11.0.1.184"
        },
        {
            "name": "NVIDIA PhysX System Software 9.23.1019",
            "version": "9.23.1019"
        },
        {
            "name": "NVIDIA FrameView SDK 1.4.10624.35034762",
            "version": "1.4.10624.35034762"
        },
        {
            "name": "NVIDIA HD Audio Driver 1.4.2.6",
            "version": "1.4.2.6"
        },
        {
            "name": "Microsoft Update Health Tools",
            "version": "5.72.0.0"
        },
        {
            "name": "MongoDB 8.0.4 2008R2Plus SSL (64 bit)",
            "version": "8.0.4"
        },
        {
            "name": "PuTTY release 0.81 (64-bit)",
            "version": "0.81.0.0"
        },
        {
            "name": "Intel(R) Computing Improvement Program",
            "version": "2.4.10910"
        },
        {
            "name": "Logi Plugin Service",
            "version": "6.0.4.21376"
        },
        {
            "name": "VMware Workstation",
            "version": "17.6.1"
        },
        {
            "name": "Visual Studio Community 2022",
            "version": "17.12.3"
        },
        {
            "name": "EVE-NG-Win-Client-Pack version 2.0",
            "version": "2.0"
        },
        {
            "name": "Microsoft Edge",
            "version": "132.0.2957.127"
        },
        {
            "name": "Nmap 7.95",
            "version": "7.95"
        },
        {
            "name": "Npcap",
            "version": "1.80"
        },
        {
            "name": "Npgsql 3.2.6",
            "version": "3.2.6-3"
        },
        {
            "name": "pgJDBC 42.7.2",
            "version": "42.7.2-1"
        },
        {
            "name": "Steam",
            "version": "2.10.91.91"
        },
        {
            "name": "WinSCP 6.3.6",
            "version": "6.3.6"
        },
        {
            "name": "Wireshark 3.0.6 64-bit",
            "version": "3.0.6"
        },
        {
            "name": "Intel(R) Wireless Bluetooth(R)",
            "version": "23.100.1.1"
        },
        {
            "name": "Realtek USB Ethernet Controller All-In-One Windows Driver",
            "version": "11.15.0327.2024"
        },
        {
            "name": "Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.40664",
            "version": "12.0.40664.0"
        },
        {
            "name": "Windows SDK AddOn",
            "version": "10.1.0.0"
        },
        {
            "name": "vs_CoreEditorFonts",
            "version": "17.7.40001"
        },
        {
            "name": "Microsoft Visual C++ 2012 Redistributable (x86) - 11.0.61030",
            "version": "11.0.61030.0"
        },
        {
            "name": "The Sims\u2122 4",
            "version": "Unknown"
        },
        {
            "name": "EA app",
            "version": "13.324.0.5837"
        },
        {
            "name": "Microsoft Windows Desktop Runtime - 8.0.7 (x64)",
            "version": "8.0.7.33814"
        },
        {
            "name": "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.42.34433",
            "version": "14.42.34433.0"
        },
        {
            "name": "Thunderbolt\u2122 Software",
            "version": "16.3.61.276"
        },
        {
            "name": "Python Launcher",
            "version": "3.10.11150.0"
        },
        {
            "name": "Microsoft Visual C++ 2013 Redistributable (x86) - 12.0.40664",
            "version": "12.0.40664.0"
        },
        {
            "name": "Apple Software Update",
            "version": "2.7.0.3"
        },
        {
            "name": "Check Point SmartConsole R81.10",
            "version": "6.9.0"
        },
        {
            "name": "Windows Software Development Kit - Windows 10.0.22000.832",
            "version": "10.1.22000.832"
        },
        {
            "name": "Intel\u00ae Driver & Support Assistant",
            "version": "24.6.49.8"
        },
        {
            "name": "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.42.34433",
            "version": "14.42.34433.0"
        },
        {
            "name": "Microsoft Visual C++ 2010  x86 Redistributable - 10.0.40219",
            "version": "10.0.40219"
        }
    ],
    "firewall_state": {
        "Domain": True,
        "Private": True,
        "Public": True
    },
    "antivirus_status": {
        "EngineVersion": "1.1.24090.11",
        "ProductVersion": "4.18.24090.11",
        "RealTimeProtection": "Enabled",
        "Antispyware": "Enabled",
        "AntispywareSignatureLastUpdated": "1/29/2025 8:15:57 AM",
        "AntispywareSignatureVersion": "1.421.1592.0",
        "Antivirus": "Enabled",
        "AntivirusSignatureLastUpdated": "1/29/2025 8:15:55 AM",
        "AntivirusSignatureVersion": "1.421.1592.0"
    },
    "smb_status": {
        "SMB1_installed": True,
        "SMB1_status": "Enabled",
        "SMB2_enabled": True
    },
    "rdp_settings": {
        "rdp_enabled": True,
        "rdp_port": 3389,
        "status": "RDP is enabled and listening on port 3389"
    },
    "local_users": [
        {
            "name": "DefaultAccount",
            "enabled": False
        },
        {
            "name": "Guest",
            "enabled": False
        },
        {
            "name": "Ilan",
            "enabled": True
        },
        {
            "name": "postgres",
            "enabled": True
        },
        {
            "name": "WDAGUtilityAccount",
            "enabled": False
        }
    ],
    "shared_folders": [
        {
            "name": "ADMIN$",
            "path": "C:\\Windows",
            "description": "Remote Admin "
        },
        {
            "name": "C$",
            "path": "C:\\",
            "description": "Default share"
        },
        {
            "name": "IPC$",
            "path": "Remote",
            "description": "IPC"
        }
    ]
}
class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-type','application/json')
        self.end_headers()
        body = {
            "data": DATA
        }
        self.wfile.write(json.dumps(body).encode())

print('[V] Client running on port: 6612')
with HTTPServer(('', 6612), handler) as server:
    server.serve_forever()