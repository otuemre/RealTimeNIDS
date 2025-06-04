import json
import pandas as pd


def parse_conn_log(filepath):
    records = []

    with open(filepath, 'r') as f:
        for line in f:
            if line.strip().startswith('#'):
                continue  # skip header/comments

            try:
                flow = json.loads(line)
                records.append(flow)
            except Exception:
                continue

    df = pd.DataFrame(records)

    # Now proceed as normal
    duration = df["duration"].astype(float).fillna(1e-6)
    fwd_bytes = df["orig_bytes"].astype(float).fillna(0)
    bwd_bytes = df["resp_bytes"].astype(float).fillna(0)
    fwd_pkts = df["orig_pkts"].astype(float).fillna(1)
    bwd_pkts = df["resp_pkts"].astype(float).fillna(1)

    total_bytes = fwd_bytes + bwd_bytes
    total_pkts = fwd_pkts + bwd_pkts

    return pd.DataFrame({
        "flow_duration": duration,
        "fwd_bytes": fwd_bytes,
        "bwd_bytes": bwd_bytes,
        "flow_bytes": total_bytes,
        "flow_byte_rate": total_bytes / duration,
        "flow_packet_rate": total_pkts / duration,
        "pkt_size_avg": total_bytes / total_pkts,
        "down_up_ratio": bwd_bytes / fwd_bytes.replace(0, 1e-6),
        "fwd_pkt_rate": fwd_pkts / duration,
        "bwd_pkt_rate": bwd_pkts / duration,
        "tcp_flags": 0,
    })
