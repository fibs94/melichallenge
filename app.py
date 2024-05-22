import scapy.all as scapy
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import pytz
import time
import os
import sqlite3
from tabulate import tabulate
import threading

DB_NAME = 'packets.db'
PROTOCOLS = {
    1: 'ICMP',
    2: 'IGMP',
    6: 'TCP',
    17: 'UDP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    88: 'EIGRP',
    89: 'OSPF'
}
lock = threading.Lock()

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_src TEXT,
            ip_dst TEXT,
            protocol INTEGER,
            size INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def store_packet(timestamp, ip_src, ip_dst, protocol, size):
    with lock:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            INSERT INTO packets (timestamp, ip_src, ip_dst, protocol, size)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, ip_src, ip_dst, protocol, size))
        conn.commit()
        conn.close()

def capture_packets(interface, duration):
    print(f"{datetime.now().isoformat()} Capturando paquetes en la interfaz {interface} durante {duration} segundos...", flush=True)
    packets = scapy.sniff(iface=interface, timeout=duration)
    print(f"{datetime.now().isoformat()} Paquetes capturados: {len(packets)}", flush=True)
    return packets

def analyze_packets(packets):
    for packet in packets:
        if packet.haslayer(scapy.IP):
            timestamp = datetime.now().isoformat()
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto
            size = len(packet)
            store_packet(timestamp, ip_src, ip_dst, protocol, size)

def get_last_5_seconds_stats():
    with lock:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        last_5_seconds = datetime.now() - timedelta(seconds=5)
        c.execute('''
            SELECT ip_src, ip_dst, protocol, size FROM packets WHERE timestamp >= ?
        ''', (last_5_seconds.isoformat(),))
        packets = c.fetchall()
        conn.close()

    protocol_count = Counter()
    protocol_size = defaultdict(int)
    ip_src_count = Counter()
    ip_src_size = defaultdict(int)
    ip_dst_count = Counter()
    ip_dst_size = defaultdict(int)

    for ip_src, ip_dst, protocol, size in packets:
        protocol_count[protocol] += 1
        protocol_size[protocol] += size
        ip_src_count[ip_src] += 1
        ip_src_size[ip_src] += size
        ip_dst_count[ip_dst] += 1
        ip_dst_size[ip_dst] += size

    total_packets = sum(protocol_count.values())
    total_size = sum(protocol_size.values())

    return total_packets, total_size, protocol_count, protocol_size, ip_src_count, ip_src_size, ip_dst_count, ip_dst_size

def get_total_packets():
    with lock:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM packets')
        total_packets = c.fetchone()[0]
        conn.close()
    return total_packets

def show_stats(total_packets, last_5_seconds_packets, last_5_seconds_size, protocol_count_5_seconds, protocol_size_5_seconds, ip_src_count, ip_src_size, ip_dst_count, ip_dst_size, execution_time):
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print(f"Fecha y hora del análisis (Chile): {datetime.now(pytz.timezone('America/Santiago'))}\n", flush=True)
    print(f"Tiempo de ejecución de la aplicación: {execution_time}", flush=True)
    print(f"Total de paquetes capturados desde el inicio: {total_packets}", flush=True)
    print(f"Total de paquetes capturados en los últimos 5 segundos: {last_5_seconds_packets}", flush=True)
    print(f"Tamaño total de los paquetes en los últimos 5 segundos: {last_5_seconds_size} bytes\n", flush=True)
    
    print("Paquetes por protocolo (últimos 5 segundos):", flush=True)
    protocol_data = []
    for proto, count in protocol_count_5_seconds.items():
        packet_percentage = (count / last_5_seconds_packets) * 100 if last_5_seconds_packets > 0 else 0
        size = protocol_size_5_seconds[proto]
        size_percentage = (size / last_5_seconds_size) * 100 if last_5_seconds_size > 0 else 0
        protocol_data.append(
            (PROTOCOLS.get(proto, proto), f"{count} ({packet_percentage:.2f}%)", f"{size} ({size_percentage:.2f}%)")
        )
    protocol_data.append(("Total", f"{last_5_seconds_packets}", f"{last_5_seconds_size} bytes"))
    print(tabulate(protocol_data, headers=["Protocolo", "Cantidad de Paquetes", "Tamaño Total (bytes)"], tablefmt="pretty"), flush=True)
    
    print("\nTop 5 IPs de origen con mayor tráfico (últimos 5 segundos):", flush=True)
    src_data = []
    for ip, count in ip_src_count.most_common(5):
        packet_percentage = (count / last_5_seconds_packets) * 100 if last_5_seconds_packets > 0 else 0
        size = ip_src_size[ip]
        src_data.append(
            (ip, f"{count} ({packet_percentage:.2f}%)", f"{size} bytes")
        )
    total_src = sum(ip_src_count.values())
    total_size_src = sum(ip_src_size.values())
    src_data.append(("Total", f"{total_src}", f"{total_size_src} bytes"))
    print(tabulate(src_data, headers=["IP de Origen", "Cantidad de Paquetes", "Tamaño Total (bytes)"], tablefmt="pretty"), flush=True)
    
    print("\nTop 5 IPs de destino con mayor tráfico (últimos 5 segundos):", flush=True)
    dst_data = []
    for ip, count in ip_dst_count.most_common(5):
        packet_percentage = (count / last_5_seconds_packets) * 100 if last_5_seconds_packets > 0 else 0
        size = ip_dst_size[ip]
        dst_data.append(
            (ip, f"{count} ({packet_percentage:.2f}%)", f"{size} bytes")
        )
    total_dst = sum(ip_dst_count.values())
    total_size_dst = sum(ip_dst_size.values())
    dst_data.append(("Total", f"{total_dst}", f"{total_size_dst} bytes"))
    print(tabulate(dst_data, headers=["IP de Destino", "Cantidad de Paquetes", "Tamaño Total (bytes)"], tablefmt="pretty"), flush=True)

def capture_and_analyze(interface, duration):
    while True:
        packets = capture_packets(interface, duration)
        analyze_packets(packets)

def main():
    interface = "eth0"
    start_time = datetime.now()
    init_db()
    capture_thread = threading.Thread(target=capture_and_analyze, args=(interface, 5))
    capture_thread.start()
    
    while True:
        last_5_seconds_packets, last_5_seconds_size, protocol_count_5_seconds, protocol_size_5_seconds, ip_src_count, ip_src_size, ip_dst_count, ip_dst_size = get_last_5_seconds_stats()
        total_packets = get_total_packets()
        execution_time = datetime.now() - start_time
        show_stats(total_packets, last_5_seconds_packets, last_5_seconds_size, protocol_count_5_seconds, protocol_size_5_seconds, ip_src_count, ip_src_size, ip_dst_count, ip_dst_size, execution_time)
        time.sleep(5)

if __name__ == "__main__":
    main()