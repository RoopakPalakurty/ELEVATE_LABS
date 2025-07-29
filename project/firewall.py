from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import subprocess

rules = {
    'block_ips': ['192.168.1.10', '10.0.0.5'],
    'block_ports': [23, 445],
    'block_protocols': ['ICMP']
}

def log_packet(pkt, reason):
    log_line = str(datetime.now()) + " - BLOCKED: " + reason + " - " + pkt.summary() + "\n"
    with open("firewall_log.txt", "a") as f:
        f.write(log_line)
    print(log_line.strip())

def enforce_iptables_rules():
    print("Applying iptables rules...")
    for ip in rules['block_ips']:
        subprocess.call(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
        print("Blocked IP at system level:", ip)

    for port in rules['block_ports']:
        subprocess.call(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP'])
        subprocess.call(['sudo', 'iptables', '-A', 'INPUT', '-p', 'udp', '--dport', str(port), '-j', 'DROP'])
        print("Blocked port at system level:", port)

    if 'ICMP' in rules['block_protocols']:
        subprocess.call(['sudo', 'iptables', '-A', 'INPUT', '-p', 'icmp', '-j', 'DROP'])
        print("Blocked ICMP at system level")

def packet_filter(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src

        if src_ip in rules['block_ips']:
            log_packet(pkt, "IP " + src_ip)
            return

        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if sport in rules['block_ports'] or dport in rules['block_ports']:
                log_packet(pkt, "TCP Port " + str(sport) + "/" + str(dport))
                return

        if UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            if sport in rules['block_ports'] or dport in rules['block_ports']:
                log_packet(pkt, "UDP Port " + str(sport) + "/" + str(dport))
                return

        if ICMP in pkt and 'ICMP' in rules['block_protocols']:
            log_packet(pkt, "ICMP packet")
            return

    print(str(datetime.now()) + " - ALLOWED: " + pkt.summary())

def main():
    print("Starting firewall...")
    enforce_iptables_rules()
    print("Sniffing packets... Press Ctrl+C to stop.")
    sniff(prn=packet_filter, store=0)

if __name__ == "__main__":
    main()
