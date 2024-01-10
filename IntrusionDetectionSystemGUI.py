import scapy.all as scapy
import tkinter as tk
from tkinter import scrolledtext
import threading

class IDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System")

        # Create GUI elements
        self.log_text = scrolledtext.ScrolledText(root, width=80, height=20)
        self.log_text.pack(pady=10)

        self.start_button = tk.Button(root, text="Start IDS", command=self.start_ids)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(root, text="Stop IDS", command=self.stop_ids, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        # Variables
        self.is_running = False

    def start_ids(self):
        self.is_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # Start a thread for packet sniffing
        self.ids_thread = threading.Thread(target=self.sniff_packets)
        self.ids_thread.start()

    def stop_ids(self):
        self.is_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        def sniff_packet(packet):
            if self.is_running:
                if packet.haslayer(scapy.IP):
                    ip_src = packet[scapy.IP].src
                    ip_dst = packet[scapy.IP].dst
                    protocol = packet[scapy.IP].proto

                    if packet.haslayer(scapy.TCP):
                        src_port = packet[scapy.TCP].sport
                        dst_port = packet[scapy.TCP].dport

                        log_message = f"TCP Packet: {ip_src}:{src_port} => {ip_dst}:{dst_port}\n"
                        self.log_text.insert(tk.END, log_message)
                        self.log_text.yview(tk.END)

                    elif packet.haslayer(scapy.UDP):
                        src_port = packet[scapy.UDP].sport
                        dst_port = packet[scapy.UDP].dport

                        log_message = f"UDP Packet: {ip_src}:{src_port} => {ip_dst}:{dst_port}\n"
                        self.log_text.insert(tk.END, log_message)
                        self.log_text.yview(tk.END)

                    elif packet.haslayer(scapy.ICMP):
                        log_message = f"ICMP Packet: {ip_src} => {ip_dst}\n"
                        self.log_text.insert(tk.END, log_message)
                        self.log_text.yview(tk.END)

        # Start sniffing the network
        scapy.sniff(prn=sniff_packet, store=False)

if __name__ == "__main__":
    root = tk.Tk()
    app = IDSApp(root)
    root.mainloop()
