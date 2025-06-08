import pandas as pd

from detection_engine import DetectionEngine
from zeek_parser import parse_conn_log


def main():
    # Load Trained Isolation Forest model
    detector = DetectionEngine()

    # Load Zeek features
    log_path = 'zeek_logs/conn.log'
    df = parse_conn_log(log_path)

    # Iterate Over Each Flow and Detect Thread
    print(f'[*] Loaded {len(df)} flows from Zeek logs.\n')
    for i, row in df.iterrows():
        features = row.to_dict()

        # Patch missing fields for compatibility with DetectionEngine
        features.setdefault('tcp_flags', 0)
        features.setdefault('packet_rate', features.get('flow_packet_rate', 0))
        features.setdefault('packet_size', features.get('pkt_size_avg', 0))
        features.setdefault('byte_rate', features.get('flow_byte_rate', 0))

        threats = detector.detect_threats(features)

        if threats:
            print(f'[!] Threat Detected in Flow {i}:')
            for t in threats:
                print(f'    → {t}')
            print('-' * 40)


if __name__ == '__main__':
    main()
