import os
import queue

from dotenv import load_dotenv
from scapy.layers.inet import IP, TCP
from sklearn.exceptions import NotFittedError

from src.realtime_nids.packet_capture import PacketCapture
from src.realtime_nids.traffic_analyzer import TrafficAnalyzer
from src.realtime_nids.detection_engine import DetectionEngine
from src.realtime_nids.alert_system import AlertSystem


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
