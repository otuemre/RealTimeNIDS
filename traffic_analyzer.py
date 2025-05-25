from collections import defaultdict
from scapy.layers.inet import IP, TCP


class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            # Update Flow Statistics
            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time

            stats['last_time'] = current_time

            return self.extract_features(packet, stats)

        return None

    def extract_features(self, packet, stats):
        duration = stats['last_time'] - stats['start_time']
        duration = duration if duration > 0 else 1e-6  # Prevent zero division with small positive fallback

        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': stats['packet_count'] / duration,
            'byte_rate': stats['byte_count'] / duration,
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }


if __name__ == "__main__":
    import time
    import os

    from packet_capture import PacketCapture
    from dotenv import load_dotenv

    analyzer = TrafficAnalyzer()
    sniffer = PacketCapture()


    def analyze_and_print(packet):
        result = analyzer.analyze_packet(packet)
        if result:
            print("[+] Feature Extracted:", result)


    # Replace with your interface name
    load_dotenv()
    interface = os.getenv("INTERFACE")

    # Override callback to use analyzer
    sniffer.packet_callback = analyze_and_print

    print("[*] Starting analysis for 10 seconds...")
    sniffer.start_capture(interface=interface)
    try:
        time.sleep(10)
    finally:
        sniffer.stop()
        print("[*] Analysis complete.")
