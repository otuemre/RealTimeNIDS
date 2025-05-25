from sklearn.ensemble import IsolationForest
import numpy as np


class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data = []

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

    def train_anomaly_detector(self, normal_traffic_data):
        self.anomaly_detector.fit(normal_traffic_data)

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
        feature_vectors = np.array([[
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate'],
        ]])

        anomaly_score = self.anomaly_detector.score_samples(feature_vectors)[0]
        if anomaly_score < -0.5:
            threats.append({
                'type': 'anomaly',
                'score': anomaly_score,
                'confidence': min(1.0, abs(anomaly_score))
            })

        return threats
