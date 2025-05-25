import queue
import threading

from scapy.all import sniff
from scapy.layers.inet import IP, TCP


class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface="eth0"):
        def capture_thread():
            sniff(iface=interface,
                  prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda _: self.stop_capture.is_set())

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()


if __name__ == "__main__":
    import time

    sniffer = PacketCapture()
    sniffer.start_capture(interface="\\Device\\NPF_{8DE4EA9F-FDC8-4DE4-8D63-D1AE347703C8}")

    try:
        print("[*] Capturing packets for 10 seconds...")
        time.sleep(10)
    finally:
        print("[*] Stopping packet capture...")
        sniffer.stop()

    # Optional: Show how many packets captured
    print(f"[*] Packets captured: {sniffer.packet_queue.qsize()}")
