#!python3
import psutil
import hashlib
import time
from cachetools import TTLCache
from scapy.all import sniff, IP, TCP
import sys

# Create a cache with a TTL of 60 seconds
cache = TTLCache(maxsize=100, ttl=60)


def get_process_hash_by_name(process_name):
    try:
        # Find the first process with the given name
        for process in psutil.process_iter(['pid', 'name']):
            if process.info['name'] == process_name:
                process_info = f"{process.info['pid']}:{process.info['name']}"
                process_hash = hashlib.sha256(process_info.encode()).hexdigest()
                return process_hash
        return None
    except psutil.NoSuchProcess:
        return None


def cache_process_hash_by_name(process_name):
    if process_name in cache:
        print(f"Hash for process '{process_name}' is already cached.")
        return cache[process_name]

    process_hash = get_process_hash_by_name(process_name)
    print(f"Process hash generated: {process_hash}")  # Added print statement
    if process_hash:
        cache[process_name] = process_hash
        print(f"Hash for process '{process_name}' cached.")
        print(f"Cached hash: {cache[process_name]}")
        return process_hash
    else:
        print(f"Process with name '{process_name}' does not exist.")
        return None


def capture_traffic(process_name):
    def packet_handler(packet):
        if IP in packet and TCP in packet:
            print(f"Packet: {packet[IP].src} -> {packet[IP].dst} | {packet[TCP].sport} -> {packet[TCP].dport}")

    print(f"Starting traffic capture for process '{process_name}'...")
    sniff(filter=f"tcp and host {process_name}", prn=packet_handler, timeout=10)


# Example usage
# process_name = "chrome.exe"  # Replace with the name of the web browser process
def hash_and_traffic(process_name):
    for i in range(30):
        print(f"Iteration {i + 1}:")
        process_hash = cache_process_hash_by_name(process_name)
        if process_hash:
            print(f"Hash of process '{process_name}': {process_hash}")
            capture_traffic(process_name)
        else:
            print(f"Process with name '{process_name}' does not exist or could not be hashed.")
        time.sleep(6)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: HashAndTraffic.py <process_name>")
        sys.exit(1)

    process_name = sys.argv[1]
    hash_and_traffic(process_name)

