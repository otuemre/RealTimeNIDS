import joblib
import pandas as pd


class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = joblib.load('models/isolation_forest.joblib')
        self.signature_rules = self.load_signature_rules()

    @staticmethod
    def load_signature_rules():
        return {
            'syn_flood': {
                'condition': lambda features: (
                        features['tcp_flags'] == 2 and
                        features['packet_rate'] > 100
                )
            },
            'port_scan': {
                'condition': lambda features: (
                        features['packet_size'] < 100 and
                        features['packet_rate'] > 50
                )
            }
        }

    def detect_threats(self, features):
        threats = []

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })

        # Anomaly-based detection
        feature_vectors = pd.DataFrame([{
            'flow_duration': features['flow_duration'],
            'fwd_bytes': features['fwd_bytes'],
            'bwd_bytes': features['bwd_bytes'],
            'flow_bytes': features['flow_bytes'],
            'flow_byte_rate': features['flow_byte_rate'],
            'flow_packet_rate': features['flow_packet_rate'],
            'pkt_size_avg': features['pkt_size_avg'],
            'down_up_ratio': features['down_up_ratio'],
            'fwd_pkt_rate': features['fwd_pkt_rate'],
            'bwd_pkt_rate': features['bwd_pkt_rate']
        }])

        anomaly_score = self.anomaly_detector.score_samples(feature_vectors)[0]
        if anomaly_score < -0.5:
            threats.append({
                'type': 'anomaly',
                'score': anomaly_score,
                'confidence': min(1.0, abs(anomaly_score))
            })

        return threats
