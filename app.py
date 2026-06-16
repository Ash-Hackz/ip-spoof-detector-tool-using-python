import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from scapy.all import ARP, sniff, srp, Ether, AsyncSniffer
import threading
import psutil
import socket
from datetime import datetime
import subprocess
import platform

ip_mac_map = {}
spoof_alerts = set()
spoofing_detected = False
sniffer = None

# --- Networking Helpers ---
def get_local_ip():
    return psutil.net_if_addrs()['Wi-Fi'][1].address if 'Wi-Fi' in psutil.net_if_addrs() else socket.gethostbyname(socket.gethostname())

def get_wifi_ssid():
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode()
            for line in output.split('\n'):
                if "SSID" in line and "BSSID" not in line:
                    return line.split(":")[1].strip()
        elif platform.system() == "Linux":
            output = subprocess.check_output(["iwgetid", "-r"]).decode().strip()
            return output
        else:
            return "Unsupported OS"
    except:
        return "Unknown"

def scan_network(log_callback):
    local_ip = get_local_ip()
    ip_range = local_ip.rsplit('.', 1)[0] + '.1/24'
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    log_callback("[*] Scanning local network...\n")
    result = srp(packet, timeout=2, verbose=0)[0]
    log_callback("{:<16} {:<18} {:<}\n".format("IP", "MAC", "Hostname"))
    for sent, received in result:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except:
            hostname = "Unknown"
        log_callback("{:<16} {:<18} {:<}\n".format(received.psrc, received.hwsrc, hostname))
        ip_mac_map[received.psrc] = received.hwsrc

# --- Detection Logic ---
def detect_spoof(packet):
    global spoofing_detected
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        known_mac = ip_mac_map.get(src_ip)
        if known_mac and known_mac != src_mac: 
            spoofing_detected = True
            update_status("Spoofing Detected!", "red")
            alert = (f"[!] Possible IP spoofing detected!\n"
                     f"    ➤ Spoofed IP: {src_ip}\n"
                     f"    ➤ Expected MAC: {known_mac}\n"
                     f"    ➤ Found MAC: {src_mac}\n")
            if alert not in spoof_alerts:
                spoof_alerts.add(alert)
                root.after(0, log_to_gui, alert)  # GUI-safe log
        else:
            ip_mac_map[src_ip] = src_mac

def start_sniffing():
    global sniffer
    sniffer = AsyncSniffer(filter="arp", prn=detect_spoof, store=False)
    sniffer.start()

def stop_after_timeout():
    global sniffer
    if sniffer:
        sniffer.stop()
        sniffer = None
    stop_button.config(state='disabled')
    start_button.config(state='normal')
    if spoofing_detected:
        log_to_gui("\n[!] IP spoofing detected during monitoring.\n")
    else:
        log_to_gui("\n[✓] No IP spoofing detected in the last 60 seconds.\n")
    update_status("Idle", "blue")

def countdown(seconds_left):
    if seconds_left > 0:
        update_status(f"Monitoring ({seconds_left}s remaining)", "green")
        root.after(1000, countdown, seconds_left - 1)
    else:
        update_status("Monitoring Completed", "pink")

# --- GUI Helpers ---
def log_to_gui(message):
    output_text.configure(state='normal')
    timestamp = datetime.now().strftime("[%H:%M:%S] ")
    output_text.insert(tk.END, timestamp + message)
    output_text.see(tk.END)
    output_text.configure(state='disabled')

def update_status(text, color="blue"):
    status_label.config(text=f"Status: {text}", fg=color)

def start_monitoring():
    global spoofing_detected
    spoofing_detected = False
    start_button.config(state='disabled')
    stop_button.config(state='normal')
    output_text.configure(state='normal')
    output_text.delete(1.0, tk.END)
    output_text.configure(state='disabled')
    log_to_gui("[*] Starting network scan and IP spoof attacks monitoring...\n")
    update_status("Scanning...", "blue")
    threading.Thread(target=lambda: scan_and_monitor_for_60s(), daemon=True).start()

def scan_and_monitor_for_60s():
    scan_network(log_to_gui)
    start_sniffing()
    countdown(60)
    root.after(60000, stop_after_timeout)

def stop_monitoring():
    global sniffer
    stop_button.config(state='disabled')
    start_button.config(state='normal')
    if sniffer:
        sniffer.stop()
        sniffer = None
    log_to_gui("\n[*] Monitoring stopped manually.\n")
    if not spoofing_detected:
        log_to_gui("[✓] No IP spoofing detected.\n")
    update_status("Idle", "blue")

def save_log():
    content = output_text.get("1.0", tk.END)
    filepath = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt")])
    if filepath:
        with open(filepath, 'w') as f:
            f.write(content)
        messagebox.showinfo("Saved", f"Log saved to {filepath}")

def toggle_theme():
    global dark_mode
    dark_mode = not dark_mode
    if dark_mode:
        root.configure(bg="#2e2e2e")
        output_text.configure(bg="#1e1e1e", fg="#ffffff", insertbackground="white")
        status_label.configure(bg="#2e2e2e", fg="#00ffcc")
        info_label.configure(bg="#2e2e2e", fg="#ffffff")
        for widget in button_frame.winfo_children():
            widget.configure(bg="#444", fg="white", activebackground="#666")
        theme_button.config(text="Light Mode")
    else:
        root.configure(bg="SystemButtonFace")
        output_text.configure(bg="white", fg="black", insertbackground="black")
        status_label.configure(bg="SystemButtonFace", fg="blue")
        info_label.configure(bg="SystemButtonFace", fg="black")
        for widget in button_frame.winfo_children():
            widget.configure(bg="SystemButtonFace", fg="black", activebackground="SystemButtonFace")
        theme_button.config(text="Dark Mode")

# --- Main App ---
root = tk.Tk()
root.title("IP Spoofing Detection Tool")
root.geometry("750x500")
root.resizable(True, True)

dark_mode = False
ssid = get_wifi_ssid()
ip_addr = get_local_ip()

info_label = tk.Label(root, text=f"Wi-Fi SSID: {ssid}    Local IP: {ip_addr}", font=("Segoe UI", 10))
info_label.pack(pady=5)

status_label = tk.Label(root, text="Status: Idle", font=("Segoe UI", 10), fg="blue")
status_label.pack(pady=(0, 5))

frame = tk.Frame(root)
frame.pack(padx=10, pady=5, fill="both", expand=True)

output_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, state='disabled', font=("Courier", 10))
output_text.pack(fill="both", expand=True)

button_frame = tk.Frame(root)
button_frame.pack(pady=8)

start_button = tk.Button(button_frame, text="Start Monitoring", width=18, command=start_monitoring)
start_button.grid(row=0, column=0, padx=10)

stop_button = tk.Button(button_frame, text="Stop Monitoring", width=18, command=stop_monitoring, state='disabled')
stop_button.grid(row=0, column=1, padx=10)

save_button = tk.Button(button_frame, text="Save Log", width=14, command=save_log)
save_button.grid(row=0, column=2, padx=10)

theme_button = tk.Button(button_frame, text="Toggle Theme", width=14, command=toggle_theme)
theme_button.grid(row=0, column=3, padx=10)

root.mainloop()
