import argparse
import threading
import queue
import curses
import time
import requests
import pcapy
import struct
import socket
import dpkt
import time
import traceback
import sys 
import os 
import json
sys.stdout = open("debug.txt", "a")
sys.stderr = sys.stdout

args = None
update_queue = queue.Queue()
data = []
data_lock = threading.RLock()
blacklist_set = set()
column_widths = [20, 20, 20, 20, 6, 8, 4,4]
blacklist_entries = 0
seen_rows = set()

# Global dictionary to track unique rows and allow updates
rows_dict = {}

def main(screen):
    try:      
        set_args()
        set_defaults(screen)
        set_header(screen)
        
        load_blacklists()
        set_header(screen)

        thread_cap = threading.Thread(target=packet_capture, daemon=True)
        thread_cap.start()

        
        thread_host = threading.Thread(target=get_reverse_dns, daemon=True)
        thread_host.start()
        
        thread_ipinfo = threading.Thread(target=get_ipinfo, daemon=True)
        thread_ipinfo.start()
    except Exception as e:
        print(e)
        exit()
        

    try:
        while True:
            update_rows(screen)
            screen.refresh()
            time.sleep(0.5)  # refresh interval
    except KeyboardInterrupt:
        pass


def get_reverse_dns():
    global rows_dict
    global args  
    global blacklist_set
    while True:
        if not rows_dict:
            time.sleep(1)
            continue
        for row in data:
            dst_ip=row["DST_IP"].strip()
            dst_host=row["DST_HOST"].strip()
            if len(dst_host) < 4:
                try:
                    hostname, aliases, _ = socket.gethostbyaddr(dst_ip)
                    mal_val = int(any(hostname.lower() in entry.lower() for entry in blacklist_set))
                    queue_update_dst_host(dst_ip, hostname,"0.0.0.0",mal_val)
                except socket.herror:
                    pass
        time.sleep(1)

def get_ipinfo():
    global rows_dict
    global args
    """
    Return (country_code, org) for `ip` using ipinfo.io.
    If token is None, will call the public/free endpoint (Lite info).
    Raises requests.HTTPError on non-200 responses.
    """
    timeout = 5.0
    cache_file = "ipinfo_cache.json"
    ipinfo_cache = {}

    # Load cache from file at startup
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r") as f:
                ipinfo_cache = json.load(f)
        except Exception as e:
            with open("error.txt", "a") as f:
                f.write(f"Failed to load cache: {e}\n")
                f.write(traceback.format_exc())

    while True:
        if not rows_dict:
            time.sleep(1)
            continue

        data = get_all_data()

        for row in data:
            dst_ip = row["DST_IP"].strip()
            if len(dst_ip) <= 4:
                continue

            # Check cache first
            cached = ipinfo_cache.get(dst_ip)
            if cached:
                country = cached.get("country")
                org = cached.get("org")
                queue_update_ipinfo(dst_ip, country)
                #print("Used IP Info Cache")
                continue

            # Not cached, fetch from ipinfo.io
            base = f"https://ipinfo.io/{dst_ip}/json"
            params = {}
            if args.token:
                params["token"] = args.token

            try:
                resp = requests.get(base, params=params, timeout=timeout)
                resp.raise_for_status()
                data = resp.json()

                country = data.get("country")
                org = data.get("org")

                # Update cache and save immediately
                ipinfo_cache[dst_ip] = {"country": country, "org": org}
                try:
                    with open(cache_file, "w") as f:
                        json.dump(ipinfo_cache, f)
                except Exception as e:
                    print(e)

                queue_update_ipinfo(dst_ip, country)

            except Exception as e:
                print(e)


        time.sleep(1)


def packet_capture():
    """Background thread function to capture packets and detect DNS responses."""
    eth_length = 14

    def process_packet(hdr, data):
        global blacklist_set
        try:
            src_ip = dst_ip = proto_str = None
            if len(data) < eth_length:
                return

            eth_type = struct.unpack('!H', data[12:14])[0]

            # ----- IPv4 -----
            if eth_type == 0x0800 and len(data) >= eth_length + 20:
                iph = struct.unpack('!BBHHHBBH4s4s', data[eth_length:eth_length+20])
                src_ip = socket.inet_ntoa(iph[8])
                dst_ip = socket.inet_ntoa(iph[9])
                protocol = iph[6]
                proto_str = "TCP" if protocol == 6 else "UDP" if protocol == 17 else str(protocol)
                ip_payload = data[eth_length + 20:]

                # Extract ports if TCP or UDP
                src_port = dst_port = None
                if protocol in (6, 17) and len(ip_payload) >= 4:
                    src_port, dst_port = struct.unpack('!HH', ip_payload[:4])

            # ----- IPv6 -----
            elif eth_type == 0x86DD and len(data) >= eth_length + 40:
                src_ip = socket.inet_ntop(socket.AF_INET6, data[eth_length+8:eth_length+24])
                dst_ip = socket.inet_ntop(socket.AF_INET6, data[eth_length+24:eth_length+40])
                next_header = data[eth_length+6]
                proto_str = "TCP" if next_header == 6 else "UDP" if next_header == 17 else str(next_header)
                ip_payload = data[eth_length + 40:]

                # Extract ports if TCP or UDP
                src_port = dst_port = None
                if next_header in (6, 17) and len(ip_payload) >= 4:
                    src_port, dst_port = struct.unpack('!HH', ip_payload[:4])

            else:
                return


            # Normal queue update for all traffic
            if src_ip and dst_ip:
                if args.src_ip is not None and src_ip is not None and args.src_ip not in src_ip:
                    xxx=0
                else:
  
                    queue_update(src_ip, dst_ip, proto=proto_str, bytes_val=1)

            # ---- DNS Detection ----
            dns_data = None
            if proto_str == "UDP":
                try:
                    udp = dpkt.udp.UDP(ip_payload)
                    if udp.dport == 53 or udp.sport == 53:
                        dns_data = dpkt.dns.DNS(udp.data)
                except Exception as e:
                    pass

            elif proto_str == "TCP":
                try:
                    tcp = dpkt.tcp.TCP(ip_payload)
                    if tcp.dport == 53 or tcp.sport == 53:
                        if len(tcp.data) > 2:
                            # Strip TCP DNS length prefix
                            dns_data = dpkt.dns.DNS(tcp.data[2:])
                except Exception as e:
                    pass

            #if dns_data:
                
                #print("DNS ID:", dns_data.id, "QR:", dns_data.qr, "Questions:", len(dns_data.qd), "Answers:", len(dns_data.an))
                #with open("dns_data.txt", "a") as e:
                #    e.write(F"{dns_data.id} {dns_data.qr} {len(dns_data.qd)} {len(dns_data.an)} \n")
                
            

            
            if dns_data and dns_data.qr == dpkt.dns.DNS_R and len(dns_data.an) > 0:
                dns_server_ip = src_ip
                for answer in dns_data.an:
                    if not isinstance(answer, dpkt.dns.DNS.RR):
                        continue

                    # Only handle A and AAAA records
                    if answer.type not in (dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA):
                        continue

                    hostname = answer.name.decode() if isinstance(answer.name, bytes) else answer.name
                    if answer.type == dpkt.dns.DNS_A:
                        ip = socket.inet_ntoa(answer.rdata)
                    else:
                        ip = socket.inet_ntop(socket.AF_INET6, answer.rdata)
                        #print(f"{hostname} -> {ip}")
                    mal_val = int(any(hostname.lower() in entry.lower() for entry in blacklist_set))
                    queue_update_dst_host(ip,hostname,dns_server_ip,mal_val)

        except Exception:
            # Catch any parsing error and continue
            return

    # Open live capture
    cap = pcapy.open_live(args.iface, 65536, 1, 0)

    # Infinite capture loop
    while True:
        try:
            (hdr, packet) = cap.next()
            if packet:
                process_packet(hdr, packet)
        except pcapy.PcapError:
            continue


def set_args():
    global args
    
    try:
        parser = argparse.ArgumentParser(description="sniffhud - Watching for privacy invading connections.")
        parser.add_argument("-i", "--iface", required=False, help="Network interface to listen on (Linux).")
        parser.add_argument("-s", "--src-ip", required=False, help="SRC_IP to watch")
        parser.add_argument("-o","--origin-country", default="US", help="Your origin country code (default: US).")
        parser.add_argument("-ip","--token", help="(optional) ipinfo.io token.")
        args = parser.parse_args()
        if args.iface is None:
            exit("--iface(-i) required. Specific network interface.")
    except Exception as e:
        print("set_args",e)
        
def load_blacklists():
    global blacklist_set
    global blacklist_entries
    blacklist_urls = []
    with open("blacklists.txt", "r") as f:
        blacklist_urls = [line.strip() for line in f if line.strip()]

    
    for url in blacklist_urls:
        try:
            resp = requests.get(url, timeout=5)
            resp.raise_for_status()
            # Split by lines and add to set

            
            
            lines = [line.strip() for line in resp.text.splitlines() if line.strip()]
            blacklist_entries += len(lines)
            blacklist_set.update(lines)
        except requests.RequestException as e:
            print(f"Failed to fetch {url}: {e}")

        print("BL Len", len(blacklist_set))
        
def queue_update_ipinfo(dst_ip, coo):
    """
    Update only the COO field for rows matching the given dst_ip.
    """
    for row_key, row in rows_dict.items():
        # row_key = (src_ip, dst_ip, proto), so check the second element
        if row_key[1] == dst_ip:
            # Update DST_HOST while keeping the column width consistent
            row["COO"] = str(coo)[:column_widths[6]].ljust(column_widths[6])            
            # Re-put updated row in the queue
            update_queue.put(row)

def queue_update_dst_host(dst_ip, dst_host,dns_src,mal):
    """
    Update only the DST_HOST field for rows matching the given dst_ip.
    """
    for row_key, row in rows_dict.items():
        # row_key = (src_ip, dst_ip, proto), so check the second element
        if row_key[1] == dst_ip:
            # Update DST_HOST while keeping the column width consistent
            row["DST_HOST"] = str(dst_host)[:column_widths[2]].ljust(column_widths[2])
            row["DNS_SRC"] = str(dns_src)[:column_widths[3]].ljust(column_widths[3])
            row["MAL"] = str(mal)[:column_widths[7]].ljust(column_widths[7])
            # Re-put updated row in the queue
            update_queue.put(row)
            
def queue_update(src_ip, dst_ip, dst_host="", dns_src="", proto="", bytes_val=0.0, coo="",mal=0):
    # Create a unique key for this row
    row_key = (src_ip, dst_ip, proto)

    if row_key in rows_dict:

        # Update existing row (increment BYTES)
        existing_row = rows_dict[row_key]
        # Convert bytes back to int, add new value, then format again
        total_bytes = int(existing_row["PKTS"].strip()) + bytes_val
        existing_row["PKTS"] = str(total_bytes).ljust(column_widths[5])
        
        # Optionally update other fields if needed
        if dst_host:
            existing_row["DST_HOST"] = str(dst_host)[:column_widths[2]].ljust(column_widths[2])
        if dns_src:
            existing_row["DNS_SRC"] = str(dns_src)[:column_widths[3]].ljust(column_widths[3])
        if coo:
            existing_row["COO"] = str(coo)[:column_widths[6]].ljust(column_widths[6])
        if mal:
            existing_row["MAL"] = str(mal)[:column_widths[7]].ljust(column_widths[7])
        
        # Re-put updated row in the queue
        update_queue.put(existing_row)
    else:
        # Create a new row
        data = {
            "SRC_IP": str(src_ip)[:column_widths[0]].ljust(column_widths[0]),
            "DST_IP": str(dst_ip)[:column_widths[1]].ljust(column_widths[1]),
            "DST_HOST": str(dst_host)[:column_widths[2]].ljust(column_widths[2]),
            "DNS_SRC": str(dns_src)[:column_widths[3]].ljust(column_widths[3]),
            "PROTO": str(proto)[:column_widths[4]].ljust(column_widths[4]),
            "PKTS": str(bytes_val).rjust(column_widths[5]),
            "COO": str(coo)[:column_widths[6]].ljust(column_widths[6]),
            "MAL": str(mal)[:column_widths[7]].ljust(column_widths[7]),
        }
        rows_dict[row_key] = data
        update_queue.put(data)


def process_update_queue():
    """
    Process all updates in the queue and apply them to the global `data` list.
    Each update is a dictionary with keys matching your columns.
    """
    while not update_queue.empty():
        update = update_queue.get()
        key_src = update["SRC_IP"]
        key_dst = update["DST_IP"]

        with data_lock:
            # Try to find existing row
            row = next((r for r in data if r["SRC_IP"] == key_src and r["DST_IP"] == key_dst), None)
            if row:
                row.update(update)  # update fields
            else:
                # Create new row
                data.append(update)

def get_all_data(sort_by_bytes=True):
    """Return a sorted copy of the current rows for safe iteration in curses."""
    with data_lock:
        rows_copy = data.copy()

    def normalize_coo(val):
        """Normalize COO: treat None, 'None', and empty as US/empty."""
        if not val:
            return ""
        val = str(val).strip().upper()
        return "" if val == "NONE" else val

    if sort_by_bytes:
        rows_copy.sort(
            key=lambda r: (
                # Non-US COO first → False for non-US, True for US/empty → non-US top
                normalize_coo(r.get("COO")) in ("US", ""),
                # MAL==1 first → False if MAL==1, True otherwise
                int(r.get("MAL", "0")) != 1,
                # Descending byte count (PKTS)
                -int(r.get("PKTS", "0").strip() or 0)
            )
        )

    return rows_copy



def update_rows(screen):
    """Redraw all rows below the header from the current data."""
    process_update_queue()  # Apply all queued updates first
    rows = get_all_data()    # Safe copy for iteration
    start_row = 2  # after header

    for i, row in enumerate(rows):
        add_row(screen, start_row + i,
                row["SRC_IP"],
                row["DST_IP"],
                row["DST_HOST"],
                row["DNS_SRC"],
                row["PROTO"],
                row["PKTS"],
                row["COO"],
                row["MAL"])


def add_test_rows():
    """
    Queue some test rows for processing by the update_rows function.
    """
    queue_update("192.168.1.2", "8.8.8.8", dst_host="google.com",
                 dns_src="192.168.1.1", proto="TCP", bytes_val=1024, coo="OK")

    queue_update("192.168.1.3", "1.1.1.1", dst_host="cloudflare.com",
                 dns_src="192.168.1.1", proto="UDP", bytes_val=512, coo="OK")

def add_row(screen, row_num, src_ip, dst_ip, dst_host, dns_src, proto, bytes_val, coo,mal):
    """
    Add a single row of data to the screen at row number `row_num`.
    Highlights the row orange if COO is not 'US'.
    """
    # Choose color based on COO
         
    if "1" in mal:
        row_style = curses.color_pair(3)
    elif "US" in coo or coo.strip() == "" or coo.strip() is None or "None" in coo:
        row_style = curses.A_NORMAL   
    else:
        row_style = curses.color_pair(2)
        
    
    # List of column values in order
    cols = [src_ip, dst_ip, dst_host, dns_src, proto, str(bytes_val), str(coo),str(mal)]

    # Draw each column
    try:
        x = 0
        for i, col in enumerate(cols):
            screen.addstr(row_num, x, col.ljust(column_widths[i]), row_style)
            x += column_widths[i] + 1
    except curses.error:
        pass

    screen.refresh()

def set_defaults(screen):
    global blacklist_entries
    try:
        curses.curs_set(0)
        screen.clear()

    # Optional: enable color and bold text
        curses.start_color()
        curses.use_default_colors()

        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
       
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_YELLOW)

        curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_RED)
    except Exception as e:
        print("set_defaults",e)
    
def set_header(screen):
    try: 
    #header_style = curses.color_pair(1) | curses.A_BOLD
        header_style = curses.A_BOLD
        normal_style = curses.A_NORMAL

        info_text = f"Black List Entries: {blacklist_entries}"
        screen.addstr(0, 0, info_text, header_style)

    # Define column headers

        headers = ["SRC_IP", "DST_IP", "DST_HOST", "DNS_SRC" ,"PROTO", "PKTS", "COO","MAL"]

    
    # Draw the header row
        x = 0
        for i, col in enumerate(headers):
            screen.addstr(1, x, col.ljust(column_widths[i]), header_style)
            x += column_widths[i] + 1
    except Exception as e:
        print("set_header",e)
        traceback.print_exc()



if __name__ == "__main__":
    curses.wrapper(main)
