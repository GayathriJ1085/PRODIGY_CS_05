import tkinter as tk
from tkinter import messagebox, scrolledtext
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    try:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto

            if TCP in packet:
                payload = packet[TCP].payload
                proto_name = "TCP"
            elif UDP in packet:
                payload = packet[UDP].payload
                proto_name = "UDP"
            else:
                payload = None
                proto_name = "Other"

            output_text.insert(tk.END, f"Source IP Address: {ip_src}\n")
            output_text.insert(tk.END, f"Destination IP Address: {ip_dst}\n")
            output_text.insert(tk.END, f"Protocol: {proto_name}\n")
            if payload:
                output_text.insert(tk.END, f"Payload Data: {str(payload)}\n")
            output_text.insert(tk.END, "-" * 50 + "\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error processing packet: {e}\n")

def start_sniffing():
    interface = interface_entry.get()
    try:
        sniff(prn=packet_callback, store=0, iface=interface, count=10, timeout=10)
    except PermissionError:
        messagebox.showerror("Permission Denied", "Please run this script with elevated privileges (root/administrator).")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while sniffing: {e}")

root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("800x600")

background_color = "#f0f0f0"
accent_color = "#4CAF50"

header_label = tk.Label(root, text="Packet Sniffer", font=("Helvetica", 24, "bold"), bg=background_color, fg="black")
header_label.pack(pady=20)

interface_frame = tk.Frame(root, bg=background_color)
interface_frame.pack(pady=10)

tk.Label(interface_frame, text="Enter Interface GUID or Name:", font=("Helvetica", 16), bg=background_color, fg="black").grid(row=0, column=0, padx=10, pady=5)
interface_entry = tk.Entry(interface_frame, font=("Helvetica", 14), width=30)
interface_entry.grid(row=0, column=1, padx=10, pady=5)

start_button = tk.Button(root, text="Start Capturing", font=("Helvetica", 14), command=start_sniffing, bg=accent_color, fg="white", relief=tk.RAISED)
start_button.pack(pady=20)

output_text = scrolledtext.ScrolledText(root, width=80, height=20, font=("Helvetica", 12))
output_text.pack(padx=10, pady=10)

root.mainloop()
