# CyberSecurityTools
A collection of cybersecurity tools written in Python.

# Python Implementation of Nmap (Pinmap)
A file with mainly one python class and virtually no 3rd party libraries. It is built to mimic the popular Nmap tool. It supports several common nmap commands and the standard input format which should make it easy to use for Nmap natives. It also has some handy stuff for programers such as an ability to output into json or a json file and methods such ARP_ping, SYN_scan, and more. Based mainly on sockets and scapy, stores data in sqlite3. Example usage below.

## Example 1: Scans two ports on two IPs, banner grabs, and outputs to json file
pmap = Pinmap("nmap  192.168.1.46,192.168.1.1 -p21-22 -sV -T5", json_filename="pinmap.json")

## Example 2: Scans one ip, 23 ports, SYN scan
pmap = Pinmap("nmap 192.168.1.1 -p 22-50 -sS")

## Example 3: Scans two ips, 4 ports, in verbose mode, gets json in variable
pmap = Pinmap("nmap 192.168.1.1-192.168.1.2 -v -p 21-22,80,443", delete_database=False)
pmap_json = pmap.convert_to_json()
pmap.delete_database()
print(pmap_json)

## Example 4: Ping scan
pmap = Pinmap("192.168.1.1-192.168.1.2 -sn -PR -dd")

## Example 5: Scans a host in debug and outputs log to a file
pmap = Pinmap("192.168.1.1 -dd", log_path="log.txt")

## Example 6: Saves the database and opens it
pmap = Pinmap("192.168.1.1", delete_database=False, database="pinmap.sql")
connection = sqlite3.connect("pinmap.sql")
c = connection.cursor()
c.execute("SELECT name FROM sqlite_schema WHERE type ='table' AND name NOT LIKE 'sqlite_%';")
tables = c.fetchall()
for table in tables:
    print(f"Tablename {table[0]}:")
    for row in c.execute(f"SELECT * FROM {table[0]}"):
        print(row)
connection.close()
pmap.remove_database()

## Example 7: Manually checking one IP's/port's responses
ip = "192.168.1.1"
port = 80
print("ACK Ping:", Pinmap.ACK_ping(ip, port))
print("SYN Ping:", Pinmap.SYN_ping(ip, port))
print("ARP Ping:", Pinmap.ARP_ping(ip))
print("ICMP Ping:", Pinmap.ICMP_ping(ip))
print("---")
print("ACK Scan:", Pinmap.ACK_scan(ip, port))
print("SYN Scan:", Pinmap.SYN_scan(ip, port))
print("XMAS Scan:", Pinmap.XMAS_scan(ip, port))
print("Basic Scan:", Pinmap.basic_scan(ip, port))
print("Banner Scan:", Pinmap.banner_scan(ip, port))

# Contribute
Contributions are encouraged:) 
