#!/usr/bin/env python3

import sys
import threading
import time
import csv
import os
from datetime import datetime
from collections import defaultdict

from scapy.all import sniff, Dot11, Dot11Elt, wrpcap, EAPOL, RadioTap
from PySide6 import QtCore, QtWidgets, QtGui
import pyqtgraph as pg

try:
    import gpsd
    GPS_AVAILABLE = True
except ImportError:
    GPS_AVAILABLE = False

ICON_MAP = {
    'AP': QtGui.QIcon.fromTheme("network-wireless"),
    'STA': QtGui.QIcon.fromTheme("computer"),
    'Phone': QtGui.QIcon.fromTheme("phone"),
    'TV': QtGui.QIcon.fromTheme("tv"),
    'Unknown': QtGui.QIcon.fromTheme("help"),
    'WPS': QtGui.QIcon.fromTheme("emblem-default"),
}

CAPTURED_HANDSHAKES = defaultdict(list)  # {bssid: [eapol_pkts]}
CAPTURED_IVS = defaultdict(list)         # {bssid: [iv_values]}
DATA_COUNT = defaultdict(int)            # {bssid: count}

def get_iface_list():
    import subprocess
    try:
        out = subprocess.check_output(['iw', 'dev']).decode()
        return [line.split()[-1] for line in out.splitlines() if 'Interface' in line]
    except Exception:
        return []

def set_interface_channel(interface, channel):
    import subprocess
    try:
        subprocess.check_output(['iwconfig', interface, 'channel', str(channel)])
    except Exception:
        pass

def parse_rsn_info(elt):
    rsn_info = {"ciphers": set(), "auths": set()}
    data = elt.info
    if elt.ID == 221 and data.startswith(b'\x00\x50\xf2\x01'):
        pos = 6
        cipher_map = {
            b'\x00\x50\xf2\x00': 'None',
            b'\x00\x50\xf2\x01': 'WEP',
            b'\x00\x50\xf2\x02': 'TKIP',
            b'\x00\x50\xf2\x04': 'CCMP',
            b'\x00\x50\xf2\x08': 'GCMP',
        }
        auth_map = {
            b'\x00\x50\xf2\x01': 'MGT',
            b'\x00\x50\xf2\x02': 'PSK',
        }
    elif elt.ID == 48:
        pos = 2
        cipher_map = {
            b'\x00\x0f\xac\x00': 'None',
            b'\x00\x0f\xac\x01': 'WEP',
            b'\x00\x0f\xac\x02': 'TKIP',
            b'\x00\x0f\xac\x04': 'CCMP',
            b'\x00\x0f\xac\x06': 'GCMP',
            b'\x00\x0f\xac\x08': 'GCMP-256',
            b'\x00\x0f\xac\x09': 'CCMP-256',
        }
        auth_map = {
            b'\x00\x0f\xac\x01': 'MGT',
            b'\x00\x0f\xac\x02': 'PSK',
            b'\x00\x0f\xac\x03': 'FT-PSK',
            b'\x00\x0f\xac\x04': 'FT-MGT',
            b'\x00\x0f\xac\x05': 'PSK-SHA256',
            b'\x00\x0f\xac\x06': 'SAE',
            b'\x00\x0f\xac\x07': 'FT-SAE',
            b'\x00\x0f\xac\x08': 'OWE',
            b'\x00\x0f\xac\x09': 'SUITEB',
            b'\x00\x0f\xac\x0a': 'SuiteB-192',
            b'\x00\x0f\xac\x0b': 'FT-EAP',
        }
    else:
        return rsn_info

    try:
        rsn_info["ciphers"].add(cipher_map.get(data[pos:pos+4], "Unknown"))
        pos += 4
        num = int.from_bytes(data[pos:pos+2], "little")
        pos += 2
        for _ in range(num):
            rsn_info["ciphers"].add(cipher_map.get(data[pos:pos+4], "Unknown"))
            pos += 4
        num = int.from_bytes(data[pos:pos+2], "little")
        pos += 2
        for _ in range(num):
            rsn_info["auths"].add(auth_map.get(data[pos:pos+4], "Unknown"))
            pos += 4
        if elt.ID == 48 and len(data) > pos:
            rsn_cap = int.from_bytes(data[pos:pos+2], "little")
            if rsn_cap & 0x80:
                rsn_info["auths"].add("MFP")
            if rsn_cap & 0x40:
                rsn_info["ciphers"].add("CMAC")
    except Exception:
        pass
    return rsn_info

def parse_network(pkt):
    bssid = pkt.addr2
    ssid = "<hidden>"
    channel = None
    signal = None
    enc = 'Open'
    auths = set()
    ciphers = set()
    wps = False

    if pkt.haslayer(Dot11Elt):
        elt = pkt[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 0 and elt.info:
                ssid = elt.info.decode(errors="ignore")
            elif elt.ID == 3:
                channel = elt.info[0]
            elif elt.ID == 221 and b'\x00P\xf2\x04' in elt.info:
                wps = True
            elif elt.ID in [48, 221]:
                rsn = parse_rsn_info(elt)
                auths.update(rsn["auths"])
                ciphers.update(rsn["ciphers"])
            elt = elt.payload if hasattr(elt, "payload") else None

    try:
        signal = pkt.dBm_AntSignal
    except Exception:
        signal = None

    if not auths and not ciphers:
        if pkt.cap & 0x10:
            enc = 'WEP'
            ciphers.add('WEP')
            auths.add('MGT')
        else:
            enc = 'Open'
            ciphers.add('None')
            auths.add('None')
    else:
        if "SAE" in auths or "OWE" in auths:
            enc = "WPA3"
        elif "PSK" in auths or "MGT" in auths or "FT-PSK" in auths or "FT-MGT" in auths or "SuiteB-192" in auths:
            enc = "WPA2"
        elif "PSK" in auths:
            enc = "WPA"
        elif "WEP" in ciphers:
            enc = "WEP"
        else:
            enc = "Unknown"

    return {
        "bssid": bssid,
        "ssid": ssid,
        "channel": channel,
        "signal": signal,
        "encryption": enc,
        "auth": ",".join(sorted(auths)),
        "cipher": ",".join(sorted(ciphers)),
        "wps": wps,
        "data": DATA_COUNT.get(bssid, 0)
    }

def parse_station(pkt, ap_bssids):
    mac = pkt.addr2
    bssid = pkt.addr1 if pkt.addr1 in ap_bssids else None
    probes = set()
    # Probe Requests
    if pkt.haslayer(Dot11Elt):
        elt = pkt[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 0 and elt.info:
                probes.add(elt.info.decode(errors="ignore"))
            elt = elt.payload if hasattr(elt, "payload") else None
    if not bssid:
        bssid_print = "(not associated)"
    else:
        bssid_print = bssid
    return {
        "mac": mac,
        "bssid": bssid_print,
        "type": "STA",
        "probes": ", ".join(probes) if probes else "",
    }

class AirSniffWorker(QtCore.QThread):
    new_network = QtCore.Signal(dict)
    new_station = QtCore.Signal(dict)
    new_packet = QtCore.Signal(object)
    handshake_captured = QtCore.Signal(str)
    iv_captured = QtCore.Signal(str)
    data_counted = QtCore.Signal(str, int)
    notify_handshake = QtCore.Signal(str)

    def __init__(self, iface, channel_hop=True, selected_channel=None):
        super().__init__()
        self.iface = iface
        self.channel_hop = channel_hop
        self.running = True
        self.captured_packets = []
        self.channels = list(range(1, 14))
        self.lock = threading.Lock()
        self.selected_channel = selected_channel

    def stop(self):
        self.running = False

    def channel_hopper(self):
        idx = 0
        while self.running and self.channel_hop:
            ch = self.channels[idx % len(self.channels)]
            set_interface_channel(self.iface, ch)
            idx += 1
            time.sleep(1.0)

    def run(self):
        if self.channel_hop:
            threading.Thread(target=self.channel_hopper, daemon=True).start()
        elif self.selected_channel:
            set_interface_channel(self.iface, self.selected_channel)

        ap_bssids = set()
        def pkt_handler(pkt):
            if pkt.haslayer(Dot11):
                # AP
                if pkt.type == 0 and pkt.subtype in [8, 5]:
                    net = parse_network(pkt)
                    ap_bssids.add(net["bssid"])
                    self.new_network.emit(net)
                # Data packets for DATA COUNT
                if pkt.type == 2 and pkt.addr2 in ap_bssids:
                    DATA_COUNT[pkt.addr2] += 1
                    self.data_counted.emit(pkt.addr2, DATA_COUNT[pkt.addr2])
                # Client/Station
                if (pkt.type == 2 or (pkt.type == 0 and pkt.subtype == 4)):
                    sta = parse_station(pkt, ap_bssids)
                    if sta:
                        self.new_station.emit(sta)
                # EAPOL handshake
                if pkt.haslayer(EAPOL):
                    bssid = pkt.addr1
                    CAPTURED_HANDSHAKES[bssid].append(pkt)
                    self.handshake_captured.emit(bssid)
                    self.notify_handshake.emit(bssid)
                # IVs (for WEP)
                if hasattr(pkt, "wepdata"):
                    bssid = pkt.addr2
                    CAPTURED_IVS[bssid].append(pkt.iv)
                    self.iv_captured.emit(bssid)
            self.lock.acquire()
            self.captured_packets.append(pkt)
            self.lock.release()
            self.new_packet.emit(pkt)

        sniff(iface=self.iface, prn=pkt_handler, store=0, stop_filter=lambda _: not self.running)

    def save_cap(self, filename):
        self.lock.acquire()
        wrpcap(filename, self.captured_packets)
        self.lock.release()

    def save_csv(self, filename, networks):
        with open(filename, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["BSSID", "SSID", "Channel", "Signal", "Encryption", "Auth", "Cipher", "WPS", "#/Data"])
            for net in networks.values():
                writer.writerow([
                    net.get("bssid"),
                    net.get("ssid"),
                    net.get("channel"),
                    net.get("signal"),
                    net.get("encryption"),
                    net.get("auth"),
                    net.get("cipher"),
                    "Yes" if net.get("wps") else "No",
                    net.get("data", 0)
                ])

class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("airSniff - Wireless Packet Sniffer")
        self.setWindowIcon(QtGui.QIcon.fromTheme("network-wireless"))
        self.networks = {}  # bssid: info
        self.stations = {}  # mac: info
        self.worker = None
        self.gps_data = None
        self.selected_bssid = None

        # Top toolbar
        self.toolbar = QtWidgets.QToolBar()
        self.iface_combo = QtWidgets.QComboBox()
        self.iface_combo.addItems(get_iface_list())
        self.start_btn = QtWidgets.QPushButton("Start")
        self.stop_btn = QtWidgets.QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.csv_btn = QtWidgets.QPushButton("Export CSV")
        self.cap_btn = QtWidgets.QPushButton("Save .cap")
        self.ch_hop_chk = QtWidgets.QCheckBox("Channel Hopping")
        self.ch_hop_chk.setChecked(True)
        self.toolbar.addWidget(QtWidgets.QLabel("Interface:"))
        self.toolbar.addWidget(self.iface_combo)
        self.toolbar.addWidget(self.start_btn)
        self.toolbar.addWidget(self.stop_btn)
        self.toolbar.addWidget(self.ch_hop_chk)
        self.toolbar.addSeparator()
        self.toolbar.addWidget(self.csv_btn)
        self.toolbar.addWidget(self.cap_btn)

        # Network selection controls
        self.select_network_btn = QtWidgets.QPushButton("Select Network")
        self.deselect_network_btn = QtWidgets.QPushButton("Deselect Network")
        self.deselect_network_btn.setEnabled(False)
        self.toolbar.addWidget(self.select_network_btn)
        self.toolbar.addWidget(self.deselect_network_btn)

        # Networks table
        self.network_table = QtWidgets.QTableWidget(0, 10)
        self.network_table.setHorizontalHeaderLabels([
            "Icon", "BSSID", "SSID", "Channel", "Signal", "Encryption", "Auth", "Cipher", "WPS", "#/Data"
        ])
        self.network_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.network_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.network_table.setColumnWidth(0, 32)
        self.network_table.setIconSize(QtCore.QSize(24, 24))

        # Stations/clients table
        self.station_table = QtWidgets.QTableWidget(0, 4)
        self.station_table.setHorizontalHeaderLabels(["Icon", "MAC", "BSSID", "Probes"])
        self.station_table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.station_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.station_table.setColumnWidth(0, 32)
        self.station_table.setIconSize(QtCore.QSize(24, 24))

        # Channel utilization graph
        self.channel_graph = pg.PlotWidget(title="Channel Utilization (2.4 GHz)")
        self.channel_graph.setYRange(0, 10)
        self.ch_bar = pg.BarGraphItem(x=list(range(1, 14)), height=[0]*13, width=0.6)
        self.channel_graph.addItem(self.ch_bar)

        # Signal level graph
        self.signal_graph = pg.PlotWidget(title="Signal Levels")
        self.signal_plot = self.signal_graph.plot([], [], pen='g', symbol='o')

        # Layout
        self.left_layout = QtWidgets.QVBoxLayout()
        self.left_layout.addWidget(self.channel_graph)
        self.left_layout.addWidget(self.signal_graph)
        self.left_layout.addWidget(self.station_table)

        self.right_layout = QtWidgets.QVBoxLayout()
        self.right_layout.addWidget(self.network_table)

        self.splitter = QtWidgets.QSplitter()
        left_widget = QtWidgets.QWidget()
        left_widget.setLayout(self.left_layout)
        right_widget = QtWidgets.QWidget()
        right_widget.setLayout(self.right_layout)
        self.splitter.addWidget(left_widget)
        self.splitter.addWidget(right_widget)

        self.main_layout = QtWidgets.QVBoxLayout(self)
        self.main_layout.addWidget(self.toolbar)
        self.main_layout.addWidget(self.splitter)

        # Connections
        self.start_btn.clicked.connect(self.start_sniff)
        self.stop_btn.clicked.connect(self.stop_sniff)
        self.csv_btn.clicked.connect(self.export_csv)
        self.cap_btn.clicked.connect(self.save_cap)
        self.select_network_btn.clicked.connect(self.select_network)
        self.deselect_network_btn.clicked.connect(self.deselect_network)
        self.network_table.itemSelectionChanged.connect(self.on_network_selected)

        # Timer for updating graphs
        self.graph_timer = QtCore.QTimer(self)
        self.graph_timer.timeout.connect(self.update_graphs)
        self.graph_timer.start(1000)

        if GPS_AVAILABLE:
            gpsd.connect()
            self.gps_timer = QtCore.QTimer(self)
            self.gps_timer.timeout.connect(self.get_gps)
            self.gps_timer.start(3000)

    def get_gps(self):
        try:
            packet = gpsd.get_current()
            if packet.mode >= 2:
                self.gps_data = (packet.lat, packet.lon)
        except Exception:
            self.gps_data = None

    def start_sniff(self):
        iface = self.iface_combo.currentText()
        ch_hop = self.ch_hop_chk.isChecked()
        sel_ch = None
        if self.selected_bssid and self.selected_bssid in self.networks:
            sel_ch = self.networks[self.selected_bssid].get("channel")
            ch_hop = False
        self.worker = AirSniffWorker(iface, channel_hop=ch_hop, selected_channel=sel_ch)
        self.worker.new_network.connect(self.add_network)
        self.worker.new_station.connect(self.add_station)
        self.worker.new_packet.connect(self.handle_packet)
        self.worker.data_counted.connect(self.update_data_count)
        self.worker.notify_handshake.connect(self.notify_handshake)
        self.worker.start()
        self.start_btn.setEnabled(False)
        self.iface_combo.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_sniff(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait()
            self.worker = None
        self.start_btn.setEnabled(True)
        self.iface_combo.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def on_network_selected(self):
        items = self.network_table.selectedItems()
        if items:
            row = items[0].row()
            bssid = self.network_table.item(row, 1).text()
            self.selected_bssid = bssid
            self.deselect_network_btn.setEnabled(True)
        else:
            self.selected_bssid = None
            self.deselect_network_btn.setEnabled(False)

    def select_network(self):
        items = self.network_table.selectedItems()
        if not items:
            QtWidgets.QMessageBox.warning(self, "Select", "Select a network (row) in the table first.")
            return
        row = items[0].row()
        bssid = self.network_table.item(row, 1).text()
        self.selected_bssid = bssid
        # Auto-stop channel hop and set to channel
        if self.worker:
            self.stop_sniff()
        self.ch_hop_chk.setChecked(False)
        QtWidgets.QMessageBox.information(self, "Selected", f"Selected network {bssid}. Channel hopping will stop and channel will be set to its channel. Start sniffing again.")
        self.deselect_network_btn.setEnabled(True)

    def deselect_network(self):
        self.selected_bssid = None
        self.ch_hop_chk.setChecked(True)
        self.network_table.clearSelection()
        self.deselect_network_btn.setEnabled(False)
        QtWidgets.QMessageBox.information(self, "Deselected", "Deselected network. Channel hopping is enabled. Start sniffing again.")

    def notify_handshake(self, bssid):
        QtWidgets.QMessageBox.information(self, "WPA-HANDSHAKE!", f"WPA-HANDSHAKE! ({bssid})")

    def add_network(self, net):
        bssid = net['bssid']
        if bssid not in self.networks:
            row = self.network_table.rowCount()
            self.network_table.insertRow(row)
            icon_item = QtWidgets.QTableWidgetItem()
            icon_item.setIcon(ICON_MAP['AP'])
            self.network_table.setItem(row, 0, icon_item)
            self.network_table.setItem(row, 1, QtWidgets.QTableWidgetItem(bssid))
            self.network_table.setItem(row, 2, QtWidgets.QTableWidgetItem(net['ssid']))
            self.network_table.setItem(row, 3, QtWidgets.QTableWidgetItem(str(net['channel'])))
            self.network_table.setItem(row, 4, QtWidgets.QTableWidgetItem(str(net['signal'])))
            self.network_table.setItem(row, 5, QtWidgets.QTableWidgetItem(net['encryption']))
            self.network_table.setItem(row, 6, QtWidgets.QTableWidgetItem(net['auth']))
            self.network_table.setItem(row, 7, QtWidgets.QTableWidgetItem(net['cipher']))
            wps_item = QtWidgets.QTableWidgetItem("Yes" if net['wps'] else "No")
            if net['wps']:
                wps_item.setIcon(ICON_MAP['WPS'])
            self.network_table.setItem(row, 8, wps_item)
            self.network_table.setItem(row, 9, QtWidgets.QTableWidgetItem(str(net['data'])))
            self.networks[bssid] = net
        else:
            for row in range(self.network_table.rowCount()):
                if self.network_table.item(row, 1).text() == bssid:
                    self.network_table.setItem(row, 2, QtWidgets.QTableWidgetItem(net['ssid']))
                    self.network_table.setItem(row, 3, QtWidgets.QTableWidgetItem(str(net['channel'])))
                    self.network_table.setItem(row, 4, QtWidgets.QTableWidgetItem(str(net['signal'])))
                    self.network_table.setItem(row, 5, QtWidgets.QTableWidgetItem(net['encryption']))
                    self.network_table.setItem(row, 6, QtWidgets.QTableWidgetItem(net['auth']))
                    self.network_table.setItem(row, 7, QtWidgets.QTableWidgetItem(net['cipher']))
                    wps_item = QtWidgets.QTableWidgetItem("Yes" if net['wps'] else "No")
                    if net['wps']:
                        wps_item.setIcon(ICON_MAP['WPS'])
                    self.network_table.setItem(row, 8, wps_item)
                    self.network_table.setItem(row, 9, QtWidgets.QTableWidgetItem(str(net['data'])))
                    break
            self.networks[bssid].update(net)

    def update_data_count(self, bssid, count):
        if bssid in self.networks:
            self.networks[bssid]['data'] = count
            for row in range(self.network_table.rowCount()):
                if self.network_table.item(row, 1).text() == bssid:
                    self.network_table.setItem(row, 9, QtWidgets.QTableWidgetItem(str(count)))
                    break

    def add_station(self, sta):
        mac = sta['mac']
        if mac not in self.stations:
            row = self.station_table.rowCount()
            self.station_table.insertRow(row)
            icon_item = QtWidgets.QTableWidgetItem()
            icon_item.setIcon(ICON_MAP.get(sta['type'], ICON_MAP['Unknown']))
            self.station_table.setItem(row, 0, icon_item)
            self.station_table.setItem(row, 1, QtWidgets.QTableWidgetItem(mac))
            self.station_table.setItem(row, 2, QtWidgets.QTableWidgetItem(sta['bssid']))
            self.station_table.setItem(row, 3, QtWidgets.QTableWidgetItem(sta['probes']))
            self.stations[mac] = sta
        else:
            for row in range(self.station_table.rowCount()):
                if self.station_table.item(row, 1).text() == mac:
                    self.station_table.setItem(row, 2, QtWidgets.QTableWidgetItem(sta['bssid']))
                    self.station_table.setItem(row, 3, QtWidgets.QTableWidgetItem(sta['probes']))
                    break
            self.stations[mac].update(sta)

    def handle_packet(self, pkt):
        pass

    def export_csv(self):
        fname, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export CSV", f"airSniff_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "CSV Files (*.csv)")
        if fname:
            if not fname.endswith(".csv"):
                fname += ".csv"
            if self.worker:
                self.worker.save_csv(fname, self.networks)
                QtWidgets.QMessageBox.information(self, "Export", f"CSV exported to {fname}")

    def save_cap(self):
        fname, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Capture", f"airSniff_{datetime.now().strftime('%Y%m%d_%H%M%S')}.cap", "PCAP Files (*.cap)")
        if fname:
            if not fname.endswith(".cap"):
                fname += ".cap"
            if self.worker:
                self.worker.save_cap(fname)
                QtWidgets.QMessageBox.information(self, "Export", f"PCAP saved to {fname}")

    def update_graphs(self):
        channels = [net.get("channel", 1) for net in self.networks.values()]
        counts = [channels.count(i) for i in range(1, 14)]
        self.ch_bar.setOpts(x=list(range(1, 14)), height=counts)
        signals = [net.get("signal") for net in self.networks.values() if net.get("signal") is not None]
        self.signal_plot.setData(list(range(len(signals))), signals)

def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.resize(1200, 700)
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
