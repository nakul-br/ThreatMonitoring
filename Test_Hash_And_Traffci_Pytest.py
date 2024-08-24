#!python3
import psutil
import hashlib
import time
import webbrowser
from scapy.all import sniff, IP, TCP
from cachetools import TTLCache

# Create a cache with a TTL of 60 seconds
cache = TTLCache(maxsize=100, ttl=60)


def get_process_hash_by_name(process_name):
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'] == process_name:
            process_info = f"{process.info['pid']}:{process.info['name']}"
            return hashlib.sha256(process_info.encode()).hexdigest()
    return None


def capture_traffic(process_name):
    def packet_handler(packet):
        if IP in packet and TCP in packet:
            print(f"Packet: {packet[IP].src} -> {packet[IP].dst} | {packet[TCP].sport} -> {packet[TCP].dport}")

    print(f"Starting traffic capture for process '{process_name}'...")
    sniff(filter=f"tcp and host {process_name}", prn=packet_handler, timeout=10)


def test_chrome_running():
    process_name = "chrome.exe"
    is_running = any(proc.info['name'] == process_name for proc in psutil.process_iter(['name']))
    assert is_running, f"Process {process_name} is not running."


def test_hash_changes_on_relaunch():
    process_name = "chrome.exe"

    # Get initial hash
    initial_hash = get_process_hash_by_name(process_name)
    print(f"\ninitial hash: {initial_hash}")
    assert initial_hash is not None, f"Process {process_name} is not running."

    # Store initial hash in cache
    cache[process_name] = initial_hash
    print(f"\ncache: {cache[process_name]}")
    # Terminate the process
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'] == process_name:
            process.terminate()
            process.wait()

    # Relaunch the process (assuming Chrome is in the PATH)
    webbrowser.open('https:://www.google.com')
    time.sleep(10)  # Wait for the process to start
    time.sleep(60)  # Wait for sufficient time for cache to expire
    # Get new hash
    new_hash = get_process_hash_by_name(process_name)
    print(f"\nnew_hash_post_relaunch: {new_hash}")
    assert new_hash is not None, f"Process {process_name} did not restart."

    # Compare new hash with cached hash
    assert initial_hash != new_hash, "Hash did not change after relaunching the process."

    # Update cache with new hash
    cache[process_name] = new_hash


def test_no_traffic_capture_if_hash_same():
    process_name = "chrome.exe"

    # Get initial hash
    initial_hash = get_process_hash_by_name(process_name)
    assert initial_hash is not None, f"Process {process_name} is not running."

    # Store initial hash in cache
    cache[process_name] = initial_hash

    time.sleep(60)  # Wait for 60 seconds

    # Get new hash
    new_hash = get_process_hash_by_name(process_name)
    assert new_hash is not None, f"Process {process_name} is not running."

    # Compare new hash with cached hash
    if initial_hash == new_hash:
        print("Hash is the same, traffic should not be captured.")
        # No traffic capture logic here
    else:
        print("Hash has changed, starting traffic capture.")
        capture_traffic(process_name)

    # Update cache with new hash
    cache[process_name] = new_hash
    initial_hash = new_hash

    # Terminate the process
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'] == process_name:
            process.terminate()
            process.wait()

    # Relaunch the process (assuming Chrome is in the PATH)
    webbrowser.open('https:://www.google.com')
    time.sleep(10)  # Wait for the process to start
    time.sleep(60)  # Wait for sufficient time for cache to expire
    # Get new hash
    new_hash = get_process_hash_by_name(process_name)
    print(f"\nnew_hash_post_relaunch: {new_hash}")
    assert new_hash is not None, f"Process {process_name} did not restart."

    if initial_hash == new_hash:
        print("Hash is the same, traffic should not be captured.")
        # No traffic capture logic here
    else:
        print("Hash has changed, starting traffic capture.")
        capture_traffic(process_name)


if __name__ == "__main__":
    import pytest

    pytest.main()
