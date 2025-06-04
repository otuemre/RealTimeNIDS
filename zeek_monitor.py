import time
import os
from detection_engine import DetectionEngine

# Path to the conn.log file in WSL
LOG_FILE = r'\\wsl$\Ubuntu\home\bytiax\Downloads\conn.log'
CHECK_INTERVAL = 1  # seconds

def tail_log(filepath, detector):
    seen_lines = set()

    while True:
        if not os.path.exists(filepath):
            time.sleep(CHECK_INTERVAL)
            continue

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    if line.startswith('#') or line in seen_lines:
                        continue
                    seen_lines.add(line)

                    fields = line.strip().split('\t')

                    if len(fields) < 20:
                        continue

                    try:
                        duration = float(fields[8]) or 1e-6
                        fwd_bytes = int(fields[9])
                        bwd_bytes = int(fields[10])
                        fwd_pkts = int(fields[16])
                        bwd_pkts = int(fields[18])

                        total_bytes = fwd_bytes + bwd_bytes
                        total_pkts = fwd_pkts + bwd_pkts

                        features = {
                            'flow_duration': duration,
                            'fwd_bytes': fwd_bytes,
                            'bwd_bytes': bwd_bytes,
                            'flow_bytes': total_bytes,
                            'flow_byte_rate': total_bytes / duration,
                            'flow_packet_rate': total_pkts / duration,
                            'pkt_size_avg': total_bytes / total_pkts if total_pkts > 0 else 0,
                            'down_up_ratio': bwd_bytes / max(fwd_bytes, 1e-6),
                            'fwd_pkt_rate': fwd_pkts / duration,
                            'bwd_pkt_rate': bwd_pkts / duration,
                            'tcp_flags': fields[11] if len(fields) > 11 else ''
                        }

                        # Patch missing fields for compatibility with DetectionEngine
                        features.setdefault('tcp_flags', '')
                        features.setdefault('packet_rate', features.get('flow_packet_rate', 0))
                        features.setdefault('packet_size', features.get('pkt_size_avg', 0))
                        features.setdefault('byte_rate', features.get('flow_byte_rate', 0))

                        threats = detector.detect_threats(features)
                        if threats:
                            print('[!] Live Threat Detect:')
                            for t in threats:
                                print(f"    → {t}")
                            print('-' * 40)
                    except Exception as inner_e:
                        print(f"[ERROR] Failed to parse line: {inner_e}")
                        continue
        except Exception as outer_e:
            print(f"[ERROR] Failed to open/read log: {outer_e}")

        time.sleep(CHECK_INTERVAL)

def main():
    print("[*] Starting real-time Zeek log monitor...")
    detector = DetectionEngine()
    tail_log(LOG_FILE, detector)

if __name__ == '__main__':
    main()
