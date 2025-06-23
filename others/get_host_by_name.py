import socket

def get_ip(domain):
    try:
        return socket.gethostbyname(domain.strip())
    except (socket.gaierror, UnicodeError) as e:
        return f"Error: {e}"

def main():
    input_file = "domains.txt"
    output_file = "ip_v4.txt"

    with open(input_file, "r") as f:
        domains = f.readlines()

    results = []
    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
        ip = get_ip(domain)
        if "Error" not in ip:
            results.append(ip)
            print(f"{domain}: {ip}")

    with open(output_file, "w") as f:
        f.write("\n".join(results))

if __name__ == "__main__":
    main()