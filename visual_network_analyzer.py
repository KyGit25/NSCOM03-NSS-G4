import sys
import threading
import time
import datetime
import requests
from collections import defaultdict, deque, Counter
from scapy.all import sniff, wrpcap, conf, get_if_list
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QComboBox, QTableWidget, QTableWidgetItem, QFileDialog
)
import matplotlib
matplotlib.use("Qt5Agg")
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import pandas as pd

# helper
def get_vendor(mac):
    if not mac:
        return "Unknown"
    # normalize and build variants (original, hex-only, OUI)
    s = mac.strip().upper()
    hexonly = "".join(c for c in s if c in "0123456789ABCDEF")
    oui = None
    if len(hexonly) >= 6:
        oui = ":".join([hexonly[i:i+2] for i in range(0, 6, 2)])
    urls = []
    # try the original, hex-only, then OUI (if available)
    urls.append(f"https://api.macvendors.com/{s}")
    if hexonly:
        urls.append(f"https://api.macvendors.com/{hexonly}")
    if oui:
        urls.append(f"https://api.macvendors.com/{oui}")
    headers = {"User-Agent": "VisualNetworkAnalyzer/1.0"}
    for url in urls:
        try:
            resp = requests.get(url, timeout=3, headers=headers)
            if resp.status_code == 200 and resp.text:
                text = resp.text.strip()
                if text and "error" not in text.lower():
                    return text
        except requests.RequestException:
            continue
    return "Unknown Vendor"

class PacketStats:
    def __init__(self, window_seconds=60):
        self.lock = threading.RLock()
        self.pkts = [] 
        self.ip_stats = defaultdict(lambda: {"packets": 0, "bytes": 0, "first_seen": None, "last_seen": None})
        self.proto_counter = Counter()
        self.total_bytes_recent = deque()  
        self.window_seconds = window_seconds
        self.total_packets = 0
        self.ip_to_mac = {}        
        self.mac_vendor_cache = {}  
        self.vendor_lock = threading.RLock()

    def add_packet(self, pkt):
        with self.lock:
            self.pkts.append(pkt)
            self.total_packets += 1
            try:
                length = len(pkt)
            except:
                length = 0
            src_ip = None
            dst_ip = None
            src_mac = None
            dst_mac = None
            proto = "OTHER"
            if pkt.haslayer(Ether):
                eth = pkt.getlayer(Ether)
                src_mac = eth.src
                dst_mac = eth.dst
                mac = pkt[Ether].src
                if pkt.haslayer(IP):
                    ip_src = pkt[IP].src
                    self.ip_to_mac[ip_src] = mac

                    # if vendor not yet resolved, mark as resolving and start background lookup
                    if mac not in self.mac_vendor_cache:
                        with self.vendor_lock:
                            # mark so we don't spawn multiple lookups for same MAC
                            self.mac_vendor_cache.setdefault(mac, "Resolving")
                        threading.Thread(
                            target=self.resolve_vendor_background, args=(mac,), daemon=True
                        ).start()

            if pkt.haslayer(ARP):
                proto = "ARP"
                if pkt.haslayer(ARP):
                    src_ip = pkt.psrc if hasattr(pkt, 'psrc') else None
                    dst_ip = pkt.pdst if hasattr(pkt, 'pdst') else None
            if pkt.haslayer(IP):
                ip = pkt.getlayer(IP)
                src_ip = ip.src
                dst_ip = ip.dst
                if pkt.haslayer(TCP):
                    proto = "TCP"
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                else:
                    proto = ip.proto if isinstance(ip.proto, str) else "IP"
            if src_ip:
                entry = self.ip_stats[src_ip]
                entry["packets"] += 1
                entry["bytes"] += length
                now = datetime.datetime.now()
                if entry["first_seen"] is None:
                    entry["first_seen"] = now
                entry["last_seen"] = now
                if "proto_counter" not in entry:
                    entry["proto_counter"] = Counter()
                entry["proto_counter"][proto] += 1
            if dst_ip:
                entry = self.ip_stats[dst_ip]
                entry.setdefault("packets", entry.get("packets", 0))
                entry.setdefault("bytes", entry.get("bytes", 0))
                entry.setdefault("first_seen", entry.get("first_seen"))
                entry.setdefault("last_seen", entry.get("last_seen"))
                entry["bytes"] += 0 
            self.proto_counter[proto] += 1
            ts = time.time()
            self.total_bytes_recent.append((ts, length))
            cutoff = ts - self.window_seconds
            while self.total_bytes_recent and self.total_bytes_recent[0][0] < cutoff:
                self.total_bytes_recent.popleft()

    def get_device_table(self):
        with self.lock:
            rows = []
            for ip, info in sorted(self.ip_stats.items(), key=lambda kv: kv[1]["bytes"], reverse=True):
                proto_counts = info.get("proto_counter", None)
                if not proto_counts:
                    proto_counts = Counter()
                most_proto = "N/A"
                if self.proto_counter:
                    proto_counter = info.get("proto_counter", Counter())
                    most_proto = proto_counter.most_common(1)[0][0] if proto_counter else "N/A"

                vendor = info.get("vendor")
                if not vendor:
                    mac = self.ip_to_mac.get(ip)
                    if mac:
                        vendor = self.mac_vendor_cache.get(mac, "Unknown")
                    else:
                        vendor = "Unknown"
                rows.append({
                    "ip": ip,
                    "protocol": most_proto,
                    "packets": info.get("packets", 0),
                    "bytes": info.get("bytes", 0),
                    "first_seen": info.get("first_seen"),
                    "last_seen": info.get("last_seen"),
                    "vendor": vendor
                })
            return rows
    
    def get_device_stats(self, ip):
        """Return stats only for a specific IP"""
        with self.lock:
            info = self.ip_stats.get(ip)
            if not info:
                return {"proto_counter": Counter(), "packets": 0, "bytes": 0, "throughput": []}
            
            # Throughput series for this IP
            now = time.time()
            cutoff = now - self.window_seconds
            buckets = defaultdict(int)
            for pkt in self.pkts:
                pkt_ip = None
                if pkt.haslayer(IP):
                    pkt_ip = pkt[IP].src
                elif pkt.haslayer(ARP):
                    pkt_ip = getattr(pkt, 'psrc', None)
                if pkt_ip == ip:
                    try:
                        length = len(pkt)
                    except:
                        length = 0
                    ts = time.time()
                    buckets[int(ts)] += length
            times = sorted(buckets.keys())
            rel_times = [t - times[0] for t in times] if times else []
            vals = [buckets[t] for t in times] if times else []
            return {"proto_counter": info.get("proto_counter", Counter()), "packets": info["packets"], "bytes": info["bytes"], "throughput": (rel_times, vals)}

    def get_top_talkers(self, topn=5):
        with self.lock:
            most = sorted(self.ip_stats.items(), key=lambda kv: kv[1]["packets"], reverse=True)[:topn]
            ips = [ip for ip, _ in most]
            packets = [info["packets"] for _, info in most]
            return ips, packets

    def get_proto_distribution(self, topn=10):
        with self.lock:
            most = self.proto_counter.most_common(topn)
            labels = [p for p, _ in most]
            values = [v for _, v in most]
            return labels, values

    def get_throughput_series(self):
        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds
            buckets = defaultdict(int)
            for ts, b in self.total_bytes_recent:
                sec = int(ts)
                buckets[sec] += b
            if not buckets:
                return [], []
            times = sorted(buckets.keys())
            rel_times = [t - times[0] for t in times]
            vals = [buckets[t] for t in times]
            return rel_times, vals

    def export_pcap(self, path):
        with self.lock:
            wrpcap(path, self.pkts)

    def resolve_vendor_background(self, mac):
        vendor = get_vendor(mac)
        # only overwrite cache if it's still unresolved/resolving or currently unknown;
        # do not clobber a previously-resolved vendor with a transient "Unknown"
        with self.vendor_lock:
            existing = self.mac_vendor_cache.get(mac)
            if existing and existing.lower() not in ("resolving", "unknown"):
                # keep existing good value
                vendor_to_set = existing
            else:
                vendor_to_set = vendor or "Unknown"
            self.mac_vendor_cache[mac] = vendor_to_set

        for ip, saved_mac in self.ip_to_mac.items():
            if saved_mac == mac and ip in self.ip_stats:
                self.ip_stats[ip]["vendor"] = vendor_to_set

class CaptureWorker(QtCore.QObject):
    packet_signal = pyqtSignal(object)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, iface=None, bpf_filter_getter=None):
        super().__init__()
        self.iface = iface
        self._stop_event = threading.Event()
        self.bpf_filter_getter = bpf_filter_getter  # callable returning current filter

    def start(self):
        threading.Thread(target=self._run_sniff, daemon=True).start()

    def stop(self):
        self._stop_event.set()

    def _run_sniff(self):
        try:
            while not self._stop_event.is_set():
                current_filter = self.bpf_filter_getter() if self.bpf_filter_getter else None
                sniff(
                    iface=self.iface,
                    prn=lambda pkt: self.packet_signal.emit(pkt),
                    store=0,
                    filter=current_filter,
                    timeout=1  # short timeout so we can check stop_event
                )
            self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))

class MplCanvas(FigureCanvas):
    def __init__(self, width=5, height=3, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi, tight_layout=True)
        self.axes = fig.add_subplot(111)
        super().__init__(fig)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Visual Network Traffic Analyzer - Prototype")
        self.setGeometry(150, 100, 1100, 700)
        self.stats = PacketStats(window_seconds=60)
        self.capture_worker = None
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout()
        central.setLayout(layout)
        ctrl_row = QHBoxLayout()
        layout.addLayout(ctrl_row)
        ctrl_row.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        self._populate_interfaces()
        ctrl_row.addWidget(self.iface_combo)

        ctrl_row.addWidget(QLabel("IP Filter:"))
        self.ip_filter_edit = QtWidgets.QLineEdit()
        self.ip_filter_edit.setPlaceholderText("e.g., 192.168.1.10")
        ctrl_row.addWidget(self.ip_filter_edit)
        self.ip_filter_edit.returnPressed.connect(self.update_ip_filter)
        
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.clicked.connect(self.toggle_capture)
        ctrl_row.addWidget(self.start_btn)
        
        self.export_btn = QPushButton("Export PCAP")
        self.export_btn.clicked.connect(self.export_pcap)
        ctrl_row.addWidget(self.export_btn)
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_ui)
        ctrl_row.addWidget(self.clear_btn)
        ctrl_row.addStretch()
        info_row = QHBoxLayout()
        layout.addLayout(info_row)
        
        self.total_pkts_label = QLabel("Packets: 0")
        self.total_bytes_label = QLabel("Recent Window Bytes: 0")
        info_row.addWidget(self.total_pkts_label)
        info_row.addWidget(self.total_bytes_label)
        info_row.addStretch()
        central_row = QHBoxLayout()
        layout.addLayout(central_row, stretch=1)
        left_box = QVBoxLayout()
        central_row.addLayout(left_box, 2)
        left_box.addWidget(QLabel("Discovered Devices (by IP)"))
        self.device_table = QTableWidget(0, 7)
        self.device_table.setHorizontalHeaderLabels(["IP", "Vendor", "Protocol", "Packets", "Bytes", "First Seen", "Last Seen"])
        self.device_table.verticalHeader().setVisible(False)
        self.device_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.device_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        left_box.addWidget(self.device_table)
        right_box = QVBoxLayout()
        central_row.addLayout(right_box, 3)

        right_box.addWidget(QLabel("Top Talkers (Packets)"))
        self.top_talkers_canvas = MplCanvas(width=5, height=3)
        right_box.addWidget(self.top_talkers_canvas, 1)

        right_box.addWidget(QLabel("Protocol Distribution"))
        self.proto_canvas = MplCanvas(width=5, height=3)
        right_box.addWidget(self.proto_canvas, 1)
        
        right_box.addWidget(QLabel("Throughput (bytes / second, rolling window)"))
        self.throughput_canvas = MplCanvas(width=5, height=3)
        right_box.addWidget(self.throughput_canvas, 1)
        
        layout.addWidget(QLabel("Activity Log"))
        self.log_widget = QtWidgets.QTextEdit()
        self.log_widget.setReadOnly(True)
        self.log_widget.setMaximumHeight(120)
        layout.addWidget(self.log_widget)
        self.refresh_timer = QtCore.QTimer()
        self.refresh_timer.timeout.connect(self.refresh_ui)
        self.refresh_timer.start(1000)
        self.known_ips = set()

    def _populate_interfaces(self):
        self.iface_combo.clear()
        try:
            for iface in conf.ifaces.values():
                friendly_name = getattr(iface, "description", None)
                guid_name = getattr(iface, "name", None)
                if friendly_name and guid_name:
                    self.iface_combo.addItem(friendly_name, guid_name)
                elif guid_name:
                    self.iface_combo.addItem(guid_name, guid_name)
                else:
                    self.iface_combo.addItem(str(iface), guid_name)
        except Exception:
            from scapy.all import get_if_list
            for i in get_if_list():
                self.iface_combo.addItem(i, i)

    def toggle_capture(self):
        if self.capture_worker is None:
            iface = self.iface_combo.currentData()
            filt = None
            self.start_capture(iface, filt)
        else:
            self.stop_capture()

    def start_capture(self, iface, bpf_filter):
        self.log(f"Starting capture on {iface} (filter: {bpf_filter})")
        self.active_ip_filter = self.ip_filter_edit.text().strip() or None
        self.capture_worker = CaptureWorker(iface=iface)
        self.capture_worker.packet_signal.connect(self.handle_packet)
        self.capture_worker.finished.connect(self.capture_finished)
        self.capture_worker.error.connect(self.capture_error)
        self.capture_worker.start()
        self.start_btn.setText("Stop Capture")
        self.log("Capture started.")

    def stop_capture(self):
        if self.capture_worker:
            self.capture_worker.stop()
            self.log("Stopping capture...")
            self.start_btn.setEnabled(False)
        else:
            self.log("No active capture to stop.")

    def capture_finished(self):
        self.log("Capture finished.")
        self.capture_worker = None
        self.start_btn.setText("Start Capture")
        self.start_btn.setEnabled(True)

    def capture_error(self, msg):
        self.log("Capture error: " + msg)
        self.capture_worker = None
        self.start_btn.setText("Start Capture")
        self.start_btn.setEnabled(True)

    def update_bpf_filter(self):
        new_filter = self.filter_edit.text().strip() or None
        self.log(f"BPF Filter updated: {new_filter}")
        # CaptureWorker will automatically use the latest filter on next sniff iteration


    def update_ip_filter(self):
        new_ip = self.ip_filter_edit.text().strip() or None
        self.log(f"IP Filter updated: {new_ip}")
        self.active_ip_filter = new_ip

    @QtCore.pyqtSlot(object)
    def handle_packet(self, pkt):
        try:
            ip_src = None
            ip_dst = None
            if pkt.haslayer(IP):
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
            elif pkt.haslayer(ARP):
                ip_src = getattr(pkt, 'psrc', None)
                ip_dst = getattr(pkt, 'pdst', None)

            # IP filter
            if hasattr(self, 'active_ip_filter') and self.active_ip_filter:
                ip_filter = self.active_ip_filter
                if ip_src != ip_filter and ip_dst != ip_filter:
                    return

            # Add packet to stats
            self.stats.add_packet(pkt)
            self.total_pkts_label.setText(f"Packets: {self.stats.total_packets}")

            # Log new device
            if ip_src and ip_src not in self.known_ips:
                self.known_ips.add(ip_src)
                self.log(f"New device discovered: {ip_src}")

        except Exception as e:
            self.log(f"Error handling packet: {e}")

    def refresh_ui(self):
        rows = self.stats.get_device_table()
        ip_filter = getattr(self, 'active_ip_filter', None)
        if ip_filter:
            rows = [r for r in rows if r["ip"] == ip_filter]

        # Update table as before
        self.device_table.setRowCount(len(rows))
        for r, info in enumerate(rows):
            self.device_table.setItem(r, 0, QTableWidgetItem(info["ip"]))
            self.device_table.setItem(r, 1, QTableWidgetItem(info.get("vendor", "Unavailable")))
            self.device_table.setItem(r, 2, QTableWidgetItem(info["protocol"]))
            self.device_table.setItem(r, 3, QTableWidgetItem(str(info["packets"])))
            self.device_table.setItem(r, 4, QTableWidgetItem(str(info["bytes"])))
            fs = info["first_seen"].strftime("%H:%M:%S") if info["first_seen"] else ""
            ls = info["last_seen"].strftime("%H:%M:%S") if info["last_seen"] else ""
            self.device_table.setItem(r, 5, QTableWidgetItem(fs))
            self.device_table.setItem(r, 6, QTableWidgetItem(ls))

        # Update Protocol Distribution graph
        self.proto_canvas.axes.clear()
        if ip_filter:
            stats = self.stats.get_device_stats(ip_filter)
            proto_counter = stats["proto_counter"]
            labels, values = zip(*proto_counter.most_common(8)) if proto_counter else ([], [])
        else:
            labels, values = self.stats.get_proto_distribution(topn=8)

        if values and sum(values) > 0:
            self.proto_canvas.axes.pie(values, labels=labels, autopct="%1.1f%%", startangle=140)
            self.proto_canvas.axes.set_title("Protocol Distribution")
        else:
            self.proto_canvas.axes.text(0.5, 0.5, "No data", ha='center', va='center')
        self.proto_canvas.draw()

        # Update Throughput graph
        self.throughput_canvas.axes.clear()
        if ip_filter:
            rel_times, vals = stats["throughput"]
        else:
            rel_times, vals = self.stats.get_throughput_series()

        if rel_times:
            t = [rt - rel_times[0] for rt in rel_times]
            self.throughput_canvas.axes.plot(t, vals, marker='o')
            self.throughput_canvas.axes.set_xlabel("Seconds")
            self.throughput_canvas.axes.set_ylabel("Bytes")
        else:
            self.throughput_canvas.axes.text(0.5, 0.5, "No throughput data", ha='center', va='center')
        self.throughput_canvas.draw()

        # Update Top Talkers
        self.top_talkers_canvas.axes.clear()
        if ip_filter:
            ips = [ip_filter]
            packets = [stats["packets"]]
        else:
            ips, packets = self.stats.get_top_talkers(topn=5)
        if packets:
            self.top_talkers_canvas.axes.barh(ips, packets, color='orange')
            self.top_talkers_canvas.axes.set_xlabel("Packets")
            self.top_talkers_canvas.axes.set_title("Top Talkers")
        else:
            self.top_talkers_canvas.axes.text(0.5, 0.5, "No data", ha='center', va='center')
        self.top_talkers_canvas.draw()


    def export_pcap(self):
        default_name = f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        path, _ = QFileDialog.getSaveFileName(self, "Save PCAP", default_name, "PCAP Files (*.pcap)")
        if not path:
            return
        try:
            self.stats.export_pcap(path)
            self.log(f"Exported {len(self.stats.pkts)} packets to {path}")
        except Exception as e:
            self.log("Failed to export pcap: " + str(e))

    def log(self, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_widget.append(f"[{ts}] {msg}")

    def clear_ui(self):
        self.log("Clearing all statistics and UI elements...")
        with self.stats.lock:
            self.stats.pkts.clear()
            self.stats.ip_stats.clear()
            self.stats.proto_counter.clear()
            self.stats.total_bytes_recent.clear()
            self.stats.total_packets = 0
        self.known_ips.clear()
        self.stats.total_packets = 0
        self.total_pkts_label.setText("Packets: 0")
        self.total_bytes_label.setText("Recent Window Bytes: 0")
        # Clear table
        self.device_table.setRowCount(0)
        # Clear canvases
        self.proto_canvas.axes.clear()
        self.throughput_canvas.axes.clear()


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()