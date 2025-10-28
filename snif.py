#!/usr/bin/env python3
"""
snif.py v1.8-pre — HUD-style network sniffer with reverse DNS, GeoIP,
country highlighting, and multi-link ACTION column.
"""

import argparse
import queue
import threading
import socket
import time
import sqlite3
import concurrent.futures
import ipaddress
from flask import Flask, render_template_string, jsonify, request
from scapy.all import sniff, IP, TCP, UDP
import ipinfo

# -------------------- Global config --------------------
RETRY_AFTER = 60
dns_executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)
dns_cache = {}
geo_cache = {}
DB_CONN = None
IPINFO_HANDLER = None
USER_COUNTRY = "US"  # default country code
FROM_IP_FILTER = None  # <--- added global variable

# -------------------- Helpers --------------------
def is_local_ip(ip: str) -> bool:
    """Return True if IP is private, local, or non-routable."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip.startswith("192.168.")
        ):
            return True
        return False
    except ValueError:
        return True

# -------------------- Reverse DNS --------------------
def async_reverse_dns(ip):
    if not ip or is_local_ip(ip):
        return ip
    if ip in dns_cache and dns_cache[ip] != ip:
        return dns_cache[ip]
    try:
        cur = DB_CONN.cursor()
        cur.execute("SELECT hostname, last_checked FROM dns_cache WHERE ip=?", (ip,))
        row = cur.fetchone()
        now = int(time.time())
        if row:
            hostname, last_checked = row[0], row[1] or 0
            dns_cache[ip] = hostname
            if hostname != ip:
                return hostname
            if now - last_checked < RETRY_AFTER:
                return hostname
    except Exception:
        pass

    def lookup():
        hostname = ip
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(f"[DNS OK] {ip} -> {hostname}")
        except Exception:
            pass
        dns_cache[ip] = hostname
        try:
            conn2 = sqlite3.connect("connections.db", check_same_thread=False)
            cur2 = conn2.cursor()
            cur2.execute(
                "INSERT OR REPLACE INTO dns_cache (ip, hostname, last_checked) VALUES (?, ?, ?)",
                (ip, hostname, int(time.time())),
            )
            conn2.commit()
            conn2.close()
        except Exception:
            pass

    dns_executor.submit(lookup)
    return dns_cache.get(ip, ip)

# -------------------- Geo lookup --------------------
def async_geo_lookup(ip):
    if not ip or not IPINFO_HANDLER or is_local_ip(ip):
        return None
    if ip in geo_cache and geo_cache[ip]:
        return geo_cache[ip]
    try:
        cur = DB_CONN.cursor()
        cur.execute("SELECT country FROM geo_cache WHERE ip=?", (ip,))
        row = cur.fetchone()
        if row and row[0]:
            geo_cache[ip] = row[0]
            return row[0]
    except Exception:
        pass

    def lookup():
        country = None
        try:
            details = IPINFO_HANDLER.getDetails(ip)
            country = details.country
            print(f"[GEO OK] {ip} -> {country}")
        except Exception:
            pass
        if not country:
            return
        geo_cache[ip] = country
        try:
            conn2 = sqlite3.connect("connections.db", check_same_thread=False)
            cur2 = conn2.cursor()
            cur2.execute(
                "INSERT OR REPLACE INTO geo_cache (ip, country, last_checked) VALUES (?, ?, ?)",
                (ip, country, int(time.time())),
            )
            conn2.commit()
            conn2.close()
        except Exception:
            pass

    dns_executor.submit(lookup)
    return geo_cache.get(ip)

# -------------------- Database setup --------------------
def init_db(db_path):
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS connections (
        from_ip TEXT,
        to_ip   TEXT,
        to_host TEXT,
        proto   TEXT,
        total_packets INTEGER DEFAULT 1,
        PRIMARY KEY (from_ip, to_ip, proto)
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS dns_cache (
        ip TEXT PRIMARY KEY,
        hostname TEXT,
        last_checked INTEGER
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS geo_cache (
        ip TEXT PRIMARY KEY,
        country TEXT,
        last_checked INTEGER
    )""")
    conn.commit()
    return conn

def update_db(conn, from_ip, to_ip, to_host, proto):
    """Insert or update connection record with retry on database lock."""
    for attempt in range(5):
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO connections (from_ip, to_ip, to_host, proto, total_packets)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(from_ip, to_ip, proto)
                DO UPDATE SET total_packets = total_packets + 1
            """, (from_ip, to_ip, to_host, proto))
            conn.commit()
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower():
                time.sleep(0.1 * (attempt + 1))
                continue
            else:
                raise

# -------------------- Flask web UI (HUD) --------------------
app = Flask(__name__)

TEMPLATE = """<!doctype html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>snif HUD</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
<style>
body {
  background: #0b0f12;
  color: #dbe7ee;
  font-family: Inter, system-ui;
  padding: 10px;
}
h2 { color: #00d1ff; margin-top: 10px; display:inline-block; }
.controls { float:right; }
.control-btn { margin-left:8px; background:#132029; color:#dbe7ee; border:1px solid rgba(255,255,255,0.03); padding:6px 10px; border-radius:6px; text-decoration:none;}
.table-dark { background-color: #141a20; border-radius: 8px; }
.table-hover tbody tr:hover { background: #1a222a; }
.alert-row td { background: linear-gradient(90deg,#8b0000,#b22222)!important; color: #fff!important; }
.country-badge { padding: 3px 7px; border-radius: 5px; background: #0f1720; color: #00d1ff; }
a { color: #00d1ff; text-decoration: none; }
a:hover { text-decoration: underline; }
.small { color:#aebcc3; font-size:0.85rem; }
</style></head>
<body>
<h2>snif HUD</h2>
<div class="controls">
  <a href="#" id="clearFilter" class="control-btn" style="display:none">Clear Filter</a>
  <a href="#" id="clearDB" class="control-btn">Clear DB</a>
</div>
<div style="clear:both"></div>
<p class="small" style="margin-top:6px;">Highlighting all traffic NOT from your country ({{ user_country }})</p>

<table class="table table-dark table-hover" style="width:100%;margin-top:10px;">
<thead><tr>
<th>FROM_IP</th><th>TO_IP</th><th>TO_HOST</th><th>COUNTRY</th><th>TOTAL PACKETS</th><th>PROTO</th><th>ACTION</th>
</tr></thead>
<tbody id="tableBody"></tbody></table>

<script>
let userCountry = "{{ user_country }}";
let filters = {};

function buildQueryParams() {
  const p = new URLSearchParams();
  if (filters.from_ip) p.set("from_ip", filters.from_ip);
  if (filters.to_ip) p.set("to_ip", filters.to_ip);
  if (filters.proto) p.set("proto", filters.proto);
  return p.toString();
}

async function refreshTable(){
  const qs = buildQueryParams();
  const res = await fetch('/data' + (qs ? ("?"+qs) : ""));
  const data = await res.json();
  const tbody=document.getElementById('tableBody');
  tbody.innerHTML='';
  data.forEach(row=>{
    const isAlert = row.country && row.country.toUpperCase() !== userCountry.toUpperCase();
    const tr=document.createElement('tr');
    if(isAlert) tr.classList.add('alert-row');
    tr.innerHTML=`
      <td><a href="#" class="from">${row.from_ip}</a></td>
      <td><a href="#" class="to">${row.to_ip}</a></td>
      <td>${row.to_host||''}</td>
      <td>${row.country ? '<span class="country-badge">'+row.country+'</span>' : ''}</td>
      <td>${row.total_packets}</td>
      <td>${row.proto}</td>
      <td>
        <a href="https://www.iplocation.net/ip-lookup?query=${row.to_ip}" target="_blank">Geo</a> |
        <a href="https://bgp.he.net/ip/${row.to_ip}" target="_blank">WHOIS</a> |
        <a href="https://www.abuseipdb.com/check/${row.to_ip}" target="_blank">Abuse</a> |
        <a href="https://www.shodan.io/host/${row.to_ip}" target="_blank">Shodan</a>
      </td>`;
    tbody.appendChild(tr);
  });
  document.getElementById('clearFilter').style.display = Object.keys(filters).length ? 'inline-block' : 'none';
}

document.addEventListener('click', function(e) {
  if (e.target.classList.contains('from')) {
    e.preventDefault();
    filters = { from_ip: e.target.innerText };
    refreshTable();
  } else if (e.target.classList.contains('to')) {
    e.preventDefault();
    filters = { to_ip: e.target.innerText };
    refreshTable();
  } else if (e.target.id === 'clearFilter') {
    e.preventDefault();
    filters = {};
    refreshTable();
  } else if (e.target.id === 'clearDB') {
    e.preventDefault();
    if (!confirm('Clear all connection records (DNS + Geo cache preserved)?')) return;
    fetch('/clear', {method:'POST'}).then(()=>refreshTable());
  }
});

refreshTable(); setInterval(refreshTable,3000);
</script>
</body></html>"""

@app.route("/")
def index():
    return render_template_string(TEMPLATE, user_country=USER_COUNTRY)

@app.route("/data")
def data():
    cur = DB_CONN.cursor()
    query = """
      SELECT c.from_ip, c.to_ip, d.hostname, g.country, c.proto, c.total_packets
      FROM connections c
      LEFT JOIN dns_cache d ON c.to_ip = d.ip
      LEFT JOIN geo_cache g ON c.to_ip = g.ip
      WHERE 1=1
    """
    params = []
    from_ip = request.args.get("from_ip")
    to_ip = request.args.get("to_ip")
    proto = request.args.get("proto")
    if from_ip:
        query += " AND c.from_ip = ?"
        params.append(from_ip)
    if to_ip:
        query += " AND c.to_ip = ?"
        params.append(to_ip)
    if proto:
        query += " AND c.proto = ?"
        params.append(proto.upper())
    query += " ORDER BY c.total_packets DESC LIMIT 100"
    cur.execute(query, params)
    rows = cur.fetchall()
    return jsonify([{"from_ip":r[0],"to_ip":r[1],"to_host":r[2],
                     "country":r[3],"proto":r[4],"total_packets":r[5]} for r in rows])

@app.route("/clear", methods=["POST"])
def clear_db():
    cur = DB_CONN.cursor()
    cur.execute("DELETE FROM connections")
    DB_CONN.commit()
    print("[INFO] Connections table cleared (DNS + Geo cache preserved).")
    return ("OK", 200)

def run_flask():
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

# -------------------- Packet capture --------------------
def packet_callback(pkt,q):
    if not pkt.haslayer(IP): return
    ip=pkt[IP]
    if pkt.haslayer(TCP):
        flags=int(pkt[TCP].flags)
        if flags in (0x10,0x12): q.put(("TCP",ip.src,ip.dst))
    elif pkt.haslayer(UDP):
        q.put(("UDP",ip.src,ip.dst))

def db_worker(q,stop_event,conn,proto_filter):
    while not stop_event.is_set() or not q.empty():
        try:
            proto,src,dst=q.get(timeout=0.5)
            if proto_filter == "tcp" and proto.upper() != "TCP": q.task_done(); continue
            if proto_filter == "udp" and proto.upper() != "UDP": q.task_done(); continue
            # --- new filter ---
            if FROM_IP_FILTER and src != FROM_IP_FILTER:
                q.task_done()
                continue
            host=async_reverse_dns(dst)
            _=async_geo_lookup(dst)
            update_db(conn,src,dst,host,proto)
            q.task_done()
        except queue.Empty:
            continue

# -------------------- Main --------------------
def main():
    global DB_CONN, IPINFO_HANDLER, USER_COUNTRY, FROM_IP_FILTER
    parser=argparse.ArgumentParser(description="snif HUD v1.8-pre")
    parser.add_argument("--iface",default=None,help="Interface to sniff on")
    parser.add_argument("--db",default="connections.db",help="SQLite DB path")
    parser.add_argument("--ipinfo-token",default=None,help="Optional ipinfo token")
    parser.add_argument("--filter",choices=["tcp","udp","both"],default="tcp",help="Protocol filter (default tcp)")
    parser.add_argument("--country-code",default="US",help="Your country code (default US)")
    parser.add_argument("--from-ip",default=None,help="Only log connections from this source IP")
    args=parser.parse_args()

    USER_COUNTRY = args.country_code.upper()
    DB_CONN = init_db(args.db)
    IPINFO_HANDLER = ipinfo.getHandler(args.ipinfo_token) if args.ipinfo_token else ipinfo.getHandler()

    FROM_IP_FILTER = args.from_ip
    if FROM_IP_FILTER:
        print(f"[INFO] Logging only connections from {FROM_IP_FILTER}")

    q=queue.Queue(maxsize=10000)
    stop_event=threading.Event()

    threading.Thread(target=run_flask,daemon=True).start()
    print(f"Web interface: http://localhost:5000  (highlighting non-{USER_COUNTRY} traffic)")

    threading.Thread(target=db_worker,args=(q,stop_event,DB_CONN,args.filter.lower()),daemon=True).start()
    print(f"Sniffing... (filter={args.filter.upper()}) Ctrl+C to stop")

    try:
        sniff_kwargs=dict(filter="ip",prn=lambda p:packet_callback(p,q),store=0)
        if args.iface: sniff_kwargs["iface"]=args.iface
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        stop_event.set(); q.join(); print("Done.")

if __name__=="__main__":
    main()
