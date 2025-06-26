import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
import tkinter as tk
from tkinter import scrolledtext

class NetworkSniffer:
    def __init__(self, master):
        self.master = master
        self.master.title("Python Network Sniffer")
        self.master.geometry("800x500")

        self.is_sniffing = False
        self.sniffer_thread = None

        self.text_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, font=("Consolas", 10))
        self.text_area.pack(expand=True, fill='both', padx=10, pady=10)

        self.start_button = tk.Button(master, text="Start Capture", command=self.start_sniffing, bg="green", fg="white", width=15)
        self.start_button.pack(side=tk.LEFT, padx=10, pady=5)

        self.stop_button = tk.Button(master, text="Stop Capture", command=self.stop_sniffing, bg="red", fg="white", width=15, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10, pady=5)

    def start_sniffing(self):
        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.is_sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=False, stop_filter=lambda x: not self.is_sniffing)

    def process_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = ""
            if TCP in packet:
                proto = "TCP"
            elif UDP in packet:
                proto = "UDP"
            elif ICMP in packet:
                proto = "ICMP"
            else:
                proto = packet[IP].proto

            payload = bytes(packet.payload)
            payload_preview = payload[:30].decode('utf-8', errors='replace')

            display_text = f"{src_ip} -> {dst_ip} | Protocol: {proto} | Payload: {payload_preview}\n"
            self.text_area.insert(tk.END, display_text)
            self.text_area.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSniffer(root)
    root.mainloop()
