"""
Packet Processing Module for NIDS (ENHANCED VERSION)

Improved packet parsing with richer features for ML detection.
"""

import threading
from typing import Callable, Optional, List, Dict, Any
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

from .logger import ThreatLogger


class PacketProcessor:
    """Processes network packets and extracts relevant features."""
    
    def __init__(self, interface: Optional[str] = None, packet_count: int = 0):
        self.interface = interface
        self.packet_count = packet_count
        self.logger = ThreatLogger()
        self.packets: List[Dict[str, Any]] = []
        self.is_running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.packet_callback: Optional[Callable] = None

    def set_packet_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        self.packet_callback = callback

    # ============================
    # 🔥 IMPROVED PARSER
    # ============================
    def _parse_packet(self, packet) -> Dict[str, Any]:
        try:
            packet_data = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': None,
                'dst_ip': None,
                'src_port': 0,
                'dst_port': 0,
                'protocol': 0,
                'protocol_name': None,
                'packet_size': len(packet),
                'payload_size': 0,
                'tcp_flags': 0,
                'flags': [],
                'raw_packet': packet
            }

            # =====================
            # IP LAYER
            # =====================
            if IP in packet:
                packet_data['src_ip'] = packet[IP].src
                packet_data['dst_ip'] = packet[IP].dst
                packet_data['payload_size'] = packet[IP].len

            # =====================
            # TCP
            # =====================
            if TCP in packet:
                packet_data['protocol'] = 6
                packet_data['protocol_name'] = 'TCP'
                packet_data['src_port'] = packet[TCP].sport
                packet_data['dst_port'] = packet[TCP].dport
                packet_data['tcp_flags'] = int(packet[TCP].flags)

                flags = []
                if packet[TCP].flags.F:
                    flags.append('FIN')
                if packet[TCP].flags.S:
                    flags.append('SYN')
                if packet[TCP].flags.R:
                    flags.append('RST')
                if packet[TCP].flags.A:
                    flags.append('ACK')

                packet_data['flags'] = flags

            # =====================
            # UDP
            # =====================
            elif UDP in packet:
                packet_data['protocol'] = 17
                packet_data['protocol_name'] = 'UDP'
                packet_data['src_port'] = packet[UDP].sport
                packet_data['dst_port'] = packet[UDP].dport

            # =====================
            # ICMP
            # =====================
            elif ICMP in packet:
                packet_data['protocol'] = 1
                packet_data['protocol_name'] = 'ICMP'

            return packet_data

        except Exception as e:
            self.logger.log_threat(
                'error',
                f'Packet parsing error: {str(e)}',
                {'error_type': type(e).__name__}
            )
            return {}

    # ============================
    # PACKET CALLBACK
    # ============================
    def _packet_sniffer_callback(self, packet) -> None:
        try:
            parsed_packet = self._parse_packet(packet)

            if not parsed_packet:
                return

            self.packets.append(parsed_packet)

            if self.packet_callback:
                self.packet_callback(parsed_packet)

        except Exception as e:
            self.logger.log_threat(
                'error',
                f'Error processing packet: {str(e)}',
                {'error_type': type(e).__name__}
            )

    # ============================
    # SNIFFING
    # ============================
    def start_sniffing(self) -> None:
        if self.is_running:
            return

        self.is_running = True

        self.sniffer_thread = threading.Thread(
            target=self._sniff_packets,
            daemon=True
        )

        self.sniffer_thread.start()

        self.logger.log_threat(
            'info',
            f'Started sniffing on: {self.interface or "ALL"}'
        )

    def _sniff_packets(self) -> None:
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_sniffer_callback,
                store=False,
                count=self.packet_count if self.packet_count > 0 else 0
            )

        except Exception as e:
            self.logger.log_threat(
                'error',
                f'Sniffing error: {str(e)}',
                {'error_type': type(e).__name__}
            )

        finally:
            self.stop_sniffing()

    def stop_sniffing(self) -> None:
        self.is_running = False

        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)

        self.logger.log_threat('info', 'Stopped packet sniffing')

    # ============================
    # UTILITIES
    # ============================
    def get_packets(self) -> List[Dict[str, Any]]:
        return self.packets.copy()

    def clear_packets(self) -> None:
        self.packets.clear()

    def get_packet_count(self) -> int:
        return len(self.packets)