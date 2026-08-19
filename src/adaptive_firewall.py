from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.ofproto import ofproto_v1_3
import time
import collections

class AdaptiveFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AdaptiveFirewall, self).__init__(*args, **kwargs)
        
        # Statistik lalu lintas
        self.packet_count = collections.defaultdict(int)
        self.packet_time = collections.defaultdict(float)
        self.suspicious_ips = {}

        # **Ambang batas awal (akan berubah seiring waktu)**
        self.base_threshold = {
            "DDoS": 1000,
            "SYN": 100,
            "SCAN": 20,
            "ICMP": 50,
            "UDP": 500
        }
        self.dynamic_threshold = self.base_threshold.copy()
        self.time_window = 10  # Waktu dalam detik untuk pengukuran

        # **Monitoring Lalu Lintas**
        self.total_packets = []
        self.update_interval = 30  # Perbarui threshold setiap 30 detik
        self.last_update_time = time.time()

    @set_ev_cls(ofp_event.EventOFPPacketIn, handler=ofp_event.HANDLER_NONBLOCKING)
    def packet_in_handler(self, ev):
        """Menangani paket masuk dan melakukan deteksi serangan"""
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser

        pkt = packet.Packet(ev.msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if not ip_pkt:
            return  # Abaikan paket non-IP

        ip_src = ip_pkt.src
        current_time = time.time()

        # **Update threshold dinamis setiap interval tertentu**
        if current_time - self.last_update_time > self.update_interval:
            self.update_dynamic_threshold()
            self.last_update_time = current_time

        # **Hitung jumlah paket dari setiap IP**
        if ip_src not in self.packet_time:
            self.packet_time[ip_src] = current_time
            self.packet_count[ip_src] = 1
        else:
            time_diff = current_time - self.packet_time[ip_src]
            if time_diff <= self.time_window:
                self.packet_count[ip_src] += 1
            else:
                self.packet_time[ip_src] = current_time
                self.packet_count[ip_src] = 1

        # **Tambahkan ke total lalu lintas**
        self.total_packets.append(self.packet_count[ip_src])

        # **Deteksi serangan jika IP belum diblokir**
        if ip_src not in self.suspicious_ips:
            if self.packet_count[ip_src] > self.dynamic_threshold["DDoS"]:
                self.block_ip(datapath, ip_src, "DDoS Attack")
            elif tcp_pkt and tcp_pkt.bits & 0x02:  # SYN flag aktif
                if self.packet_count[ip_src] > self.dynamic_threshold["SYN"]:
                    self.block_ip(datapath, ip_src, "SYN Flood")
            elif tcp_pkt and self.packet_count[ip_src] > self.dynamic_threshold["SCAN"]:
                self.block_ip(datapath, ip_src, "Port Scanning")
            elif icmp_pkt and self.packet_count[ip_src] > self.dynamic_threshold["ICMP"]:
                self.block_ip(datapath, ip_src, "ICMP Flood")
            elif udp_pkt and self.packet_count[ip_src] > self.dynamic_threshold["UDP"]:
                self.block_ip(datapath, ip_src, "UDP Flood")

    def update_dynamic_threshold(self):
        """Menghitung threshold dinamis berdasarkan lalu lintas rata-rata"""
        if self.total_packets:
            avg_traffic = sum(self.total_packets) / len(self.total_packets)
            self.dynamic_threshold["DDoS"] = max(int(avg_traffic * 2), self.base_threshold["DDoS"])
            self.dynamic_threshold["SYN"] = max(int(avg_traffic * 0.2), self.base_threshold["SYN"])
            self.dynamic_threshold["SCAN"] = max(int(avg_traffic * 0.05), self.base_threshold["SCAN"])
            self.dynamic_threshold["ICMP"] = max(int(avg_traffic * 0.1), self.base_threshold["ICMP"])
            self.dynamic_threshold["UDP"] = max(int(avg_traffic * 0.5), self.base_threshold["UDP"])

            # Log perubahan threshold
            self.logger.info(f"🔄 Update Threshold Dinamis: {self.dynamic_threshold}")

        # Reset data lalu lintas untuk iterasi berikutnya
        self.total_packets = []

    def block_ip(self, datapath, ip_src, attack_type):
        """Blokir IP yang melakukan serangan dan log jenis serangan"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Membuat aturan OpenFlow untuk memblokir IP penyerang
        match = parser.OFPMatch(ipv4_src=ip_src)
        actions = []  # Tidak ada aksi, paket akan dibuang
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, match=match, instructions=inst, priority=10)
        datapath.send_msg(mod)

        # Simpan IP ke daftar blokir
        self.suspicious_ips[ip_src] = time.time()

        # Log deteksi serangan
        self.logger.info(f"[⚠️ WARNING] Serangan {attack_type} terdeteksi dari IP {ip_src}. IP diblokir!")

    @set_ev_cls(ofp_event.EventOFPStateChange, handler=ofp_event.HANDLER_BEFORE)
    def state_change_handler(self, ev):
        """Reset daftar statistik jika switch mengalami perubahan status"""
        if ev.state == ofproto_v1_3.OFPPR_ADD:
            self.packet_count.clear()
            self.packet_time.clear()
            self.suspicious_ips.clear()
