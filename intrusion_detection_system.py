import os
import queue

from dotenv import load_dotenv
from scapy.layers.inet import IP, TCP
from sklearn.exceptions import NotFittedError

from packet_capture import PacketCapture
from traffic_analyzer import TrafficAnalyzer
from detection_engine import DetectionEngine
from alert_system import AlertSystem


class IntrusionDetectionSystem:
    def __init__(self, interface="eth0"):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()

        load_dotenv()
        self.interface = os.getenv("INTERFACE")

    def start(self):
        print(f"[*] Starting capture on Interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        ### FIT THE MODEL BEFORE DETECTION ###
        print("[*] Collecting training data for anomaly detection...")
        training_features = []

        while len(training_features) < 100:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=5)
                features = self.traffic_analyzer.analyze_packet(packet)
                if features:
                    vec = [
                        features['packet_size'],
                        features['packet_rate'],
                        features['byte_rate']
                    ]
                    training_features.append(vec)
            except queue.Empty:
                print("[!] Timeout while collecting training data.")
                break

        if len(training_features) > 0:
            self.detection_engine.train_anomaly_detector(training_features)
            print(f"[*] Trained IsolationForest on {len(training_features)} samples.")
        else:
            print("[!] No training data collected. Anomaly detection disabled.")

        ### DETECT THE ANOMALIES ###
        print("[*] Entering detection loop...")

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)

                if features:
                    threats = self.detection_engine.detect_threats(features)

                    for threat in threats:
                        packet_info = {
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst,
                            'source_port': packet[TCP].sport,
                            'destination_port': packet[TCP].dport
                        }

                        self.alert_system.generate_alert(threat, packet_info)
            except queue.Empty:
                pass
            except NotFittedError:
                print("[!!!] The IsolationTree Model is NOT fitted! Please fit it first!")
                print("Stopping IDS...")
                self.packet_capture.stop_capture()
                break
            except TypeError:
                print("Stopping IDS...")
                self.packet_capture.stop_capture()
                break
            except KeyboardInterrupt:
                print("Stopping IDS...")
                self.packet_capture.stop_capture()
                break

if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.start()
