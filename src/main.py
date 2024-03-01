from scanner import get_ip, scan_ip, get_scan_results, use_ports


def main():

   


    ip = get_ip()
    nm = scan_ip(ip)
    if nm is not None:
        open_ports = get_scan_results(nm, ip)
        if open_ports is not None:
            use_ports(open_ports)

if __name__ == "__main__":
    main()