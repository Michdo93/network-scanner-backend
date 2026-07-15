import os
import socket
import dns.resolver
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt"
}

# Hilfsfunktion zur Auflösung von Hostnamen in IPs
def resolve_host(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

# 1. TCP-Ping (Prüfen, ob Host erreichbar ist)
@app.route('/scan/ping', methods=['POST'])
def ping_host():
    data = request.json or {}
    target = data.get('target', '').strip()
    port = int(data.get('port', 80))

    if not target:
        return jsonify({"error": "Kein Ziel angegeben"}), 400

    ip = resolve_host(target)
    if not ip:
        return jsonify({"success": False, "error": "Host-Auflösung fehlgeschlagen"}), 400

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0) # 3 Sekunden Timeout
    
    try:
        s.connect((ip, port))
        s.close()
        return jsonify({
            "success": True,
            "target": target,
            "ip": ip,
            "status": "online",
            "message": f"Verbindung erfolgreich hergestellt auf Port {port}."
        })
    except Exception as e:
        return jsonify({
            "success": True,
            "target": target,
            "ip": ip,
            "status": "offline",
            "message": "Verbindung fehlgeschlagen oder Timeout."
        })

# 2. Port-Scanner
@app.route('/scan/ports', methods=['POST'])
def port_scan():
    data = request.json or {}
    target = data.get('target', '').strip()
    custom_ports = data.get('ports', [])

    if not target:
        return jsonify({"error": "Kein Ziel angegeben"}), 400

    ip = resolve_host(target)
    if not ip:
        return jsonify({"error": "Host konnte nicht aufgelöst werden"}), 400

    # Ports bestimmen: Entweder User-Auswahl oder unsere Common-Liste
    ports_to_scan = [int(p) for p in custom_ports if str(p).isdigit()]
    if not ports_to_scan:
        ports_to_scan = list(COMMON_PORTS.keys())

    results = []

    # Einfacher, sequentieller Portscan (für Render Free-Tier optimiert)
    for port in ports_to_scan:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0) # Schneller Timeout pro Port
        result = s.connect_ex((ip, port))
        
        service = COMMON_PORTS.get(port, "Unbekannter Dienst")
        if result == 0:
            results.append({"port": port, "service": service, "status": "open"})
        else:
            results.append({"port": port, "service": service, "status": "closed"})
        s.close()

    return jsonify({
        "target": target,
        "ip": ip,
        "results": results
    })

# 3. DNS-Lookup Tool
@app.route('/scan/dns', methods=['POST'])
def dns_lookup():
    data = request.json or {}
    domain = data.get('target', '').strip()

    if not domain:
        return jsonify({"error": "Keine Domain angegeben"}), 400

    records = ['A', 'AAAA', 'MX', 'TXT', 'NS']
    results = {}

    for r_type in records:
        try:
            answers = dns.resolver.resolve(domain, r_type)
            results[r_type] = [str(rdata) for rdata in answers]
        except Exception:
            results[r_type] = [] # Keine Einträge gefunden oder Fehler

    return jsonify({
        "domain": domain,
        "dns_records": results
    })

if __name__ == '__main__':
    app.run(port=8080)
