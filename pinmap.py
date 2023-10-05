import socket
import logging 
import ipaddress
import sqlite3
import re
import threading
from datetime import datetime
import time
import random
import os
import json
import sys

try:
    from scapy.all import IP, ICMP, sr1, TCP, sr, UDP, arping # To Remove UDP, sr1
except ImportError as e:
    logging.warning("Scapy could not be imported. Run 'pip3 install scapy' to fix")

# TO DO: 
# -sU: Perform a UDP scan.
# Add output as xml? 
# Add better closed/open/filtered results

# Layout (may not be updated... its not):
# __init__
# ping
# SYN_scan
# banner_scan
# basic_scan
# _Pinmap__scan_port
# _Pinmap__start_port_thread
# _Pinmap__parse_port_str
# _Pinmap__make_ip_table
# _Pinmap__start_ip_thread
# _Pinmap__parse_ip_str
# convert_to_json
# _Pinmap__start_pinmap

# Init calls _Pinmap__start_pinmap which then works its way upwards (skipping convert_to_json)

class PinmapInputError(Exception):
    """ This is used for all errors Pinmap explicitly raises """
    pass

class Pinmap:
    """Mimic the popular Nmap command line tool using sockets and scapy    
    Usage:
    Pinmap("-p 20-22,80,443 192.168.1.1/24 -v")
    Pinmap("-Pn 192.168.1.1-192.168.2.3", database = "pinmap.sql", delete_database=False, json_filename='pinmap.json')

    Some Large Differences from Nmap:
    Nmap defaults to the top 1000 ports, Pinmap to the top like 100
    Nmap defaults to SYN, Pinmap to basic_scan 
    Nmap has several flags and features (scripts) without support in Pinmap
    Nmap has some functionality (convert to json) not in Pinmap 
    Nmap -sV does something other than banner grabbing, but Pinmap does banner grabbing for that
    """
    NMAP_HELP = """ """ # TO ADD
    f_time = 0 # Speed, lower is faster
    port_str = "20-23,25,53,67-68,69,80,110,119,123,137-139,143,161-162,179,194,389,443,445,465,514-515,587,636,993-995,1080,1433-1434,1701,1723,3306,3389,5060,5222,5269,5432,5900-5901,8080,8443,9100,9200,11211,27017"
    ping_sweep = True # Ping before scanning ports
    ping_scan = False # Only ping, no port scans
    single_scan = False # Scanning one IP
    verbose = False # Verbosity level, -v or -vv
    ips_scanned = 0 # Count
    hosts_up = 0 # Count
    ip_level_threads = [] # Depreciated since this caused a race condition with sqlite... Whoops
    scan_type = "basic"
    debug_level = 0
    ping_method = "ICMP"
    ip_regex = r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"

    def __init__(self, input_str, database = "pinmap.sql", delete_database=True, file=None, json_filename=False, silence_prints=False, log_path=False):
        """ Arguments:
        input_str (type=str) -- the nmap command
        database (type=str) -- the sqlite3 database to put each ip table in (default pinmap.sql)
        delete_database (type=bool) -- whether or not to delete the database when done (default True)
        file (type=fileobj) -- a writable file object to print the output to (default None)
        json_filename (type=str) -- will write the scan results in json to path (default False)
        silence_prints(type=bool) -- will silence all print statements (not errors) (default False)
        log_path(type=str) -- will write log to that path if provided. Consider -d or -dd if using this (default False)
        
        Currently input_str has support for:
            -T = Time 0(slowest) to 5(fastest) 
            -p = Port numbers
            -pn = Scan ports even if fail ping
            -sS, -sA, -sX = SYN Scan, ACK Scan, XMAS scan
            -sN, sF = NULL Scan, FIN scan
            -sV = Get Version Info (Banner scan)
            -v = Verbose
            -d/-dd = Increase debug level
            -sn = Ping scan only
            -PR, -PA, -PS = ARP Ping, ACK ping, SYN ping
        """
        self.ips_to_scan = []
        self.ips_latency = []
        self.ports_to_scan = []
        self.port_level_threads = []
        self.last_scan = [] 
        self.file = file
        self.silence_prints= silence_prints
        if silence_prints: sys.stdout = open(os.devnull, 'w')
        print(f"Starting Pinmap 1.00 (Python version of https://nmap.org) at {datetime.now()}", file=self.file)
        self.database = database
        self.delete_database = delete_database
        self.json_filename = json_filename
        
        #####################
        # Process input_str #
        #####################

        parts = input_str.split(" ")
        ips = []
        skip = 0
        for part_ind in range(len(parts)):
            if skip:
                skip = 0
                continue
            part = parts[part_ind]
            if part.startswith("-"):
                if part == "-p":
                    try: 
                        self.port_str = parts[part_ind+1]
                        skip = 1
                    except Exception as e: raise PinmapInputError("-p must be followed by a port number(s)") from e
                elif part.startswith("-p"):
                    self.port_str = part.replace("-p", "")
                elif part == "-T":
                    self.f_time = (5 - parts[part_ind+1])
                    logging.info(f"Time set to {self.f_time}")
                elif part.startswith("-T"):
                    self.f_time = (5 - int(part.replace("-T", "")))
                    logging.info(f"Time set to {self.f_time}")
                elif part.startswith("-Pn"):
                    self.ping_sweep = False
                elif part.startswith("-sS"):
                    self.scan_type = "SYN"
                elif part.startswith("-sV"):
                    self.scan_type = "Banner"
                elif part.startswith("-sF"):
                    self.scan_type = "FIN"
                elif part.startswith("-sN"):
                    self.scan_type = "NULL"
                elif part.startswith("-sA"):
                    self.scan_type = "ACK"
                elif part.startswith("-sX"):
                    self.scan_type = "XMAS"
                elif part.startswith("-sU"):
                    self.scan_type = "UDP"
                elif part.startswith("-PR"):
                    self.ping_method = "ARP"
                elif part.startswith("-PA"):
                    self.ping_method = "ACK"
                elif part.startswith("-PS"):
                    self.ping_method = "SYN"
                elif part == "-v" or part == "-vv":
                    self.verbose = part
                elif part.startswith("-sn"):
                    self.ping_scan = True
                elif part.startswith("-d"):
                    self.debug_level += part.count("d")
                elif part.startswith("-h"):
                    print(self.NMAP_HELP)
                    return
            # Validate IP Address
            elif re.match(self.ip_regex, part):
                ips.append(part)
        
        ##################
        # Set Up Logging #
        ##################

        FORMAT = "%(asctime)s: %(levelname)s: %(message)s (File %(filename)s: Function %(funcName)s: Line %(lineno)d)"
        handlers = [logging.StreamHandler(sys.stdout)]
        if self.debug_level == 1: level = logging.INFO
        elif self.debug_level == 2: level = logging.DEBUG
        else: level = logging.WARNING
        if log_path: handlers.append(logging.FileHandler(log_path, "a"))
        logging.basicConfig(
            level=level,
            datefmt='%H:%M:%S',
            format=FORMAT,
            handlers=handlers
        )
        logging.getLogger("scapy").setLevel(logging.CRITICAL) # Otherwise it outputs warnings
        logging.debug(f"ping_method: {self.ping_method}")
        logging.debug(f"scan_type: {self.scan_type}")

        # set single_scan then start
        if len(ips) == 1 and "/" not in ips[0] and "," not in ips[0] and "-" not in ips[0]:
            self.single_scan = True
        self.__start_pinmap(",".join(ips))

    def __start_pinmap(self, ip_str):
        """Start timer, start pinmap by proccessing up"""
        logging.debug("Ingress")
        start = datetime.now()
        logging.info(f"ip_str = '{ip_str}'")
        logging.info(f"port_str = '{self.port_str}'")

        for ip in self.__class__.parse_ip_str(ip_str):
            self.__start_ip_thread(ip)

        self.__end_pinmap(start)

    @staticmethod
    def validate_ip(ip):
        ip_regex = r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
        ip = ip.strip()
        if re.fullmatch(ip_regex, ip): return ip
        else: raise PinmapInputError(f"{ip} is not a valid ip address")
    
    @staticmethod
    def parse_ip_str(ip_str):
        """ Generator to parse ips in these formats: ip-ip,ip,ip,ip/24 """
        # ip_regex = r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
        # def validate_ip(ip):
        #     ip = ip.strip()
        #     if re.fullmatch(ip_regex, ip): return ip
        #     else: raise PinmapInputError(f"{ip} is not a valid ip address")

        def subparse_ip_str(ip_str):
            if "-" in ip_str:
                ips = ip_str.split("-")
                if len(ips) > 2: 
                    raise PinmapInputError("The IP Addressess are not properly formatted")
                for ip in range(int(ipaddress.ip_address(ips[0])), int(ipaddress.ip_address(ips[1]))+1):
                    yield Pinmap.validate_ip(str(ipaddress.ip_address(ip)))
            elif "/" in ip_str:
                for ip in ipaddress.ip_network(ip_str, False).hosts():
                    yield Pinmap.validate_ip(str(ipaddress.ip_address(ip)))
            else:
                yield Pinmap.validate_ip(ip_str)

        if "," in ip_str:
            for ip_section in ip_str.split(","):
                for ip in subparse_ip_str(ip_section):
                    yield ip
        else:
            for ip in subparse_ip_str(ip_str):
                yield ip

    def __start_ip_thread(self, *args, **kwargs):
        """ Now a pass through due to race condition. Call __make_ip_table """
        logging.debug("Ingress")
        # x = threading.Thread(target=self.__scan_ports_wrapper, args=args)
        # x.start()
        # self.ip_level_threads.append(x)
        self.__make_ip_table(*args, **kwargs) 
        # Did not do threading due to sqlite error database locked

    def __make_ip_table(self, ip):
        """ Pass ip and port_str. Make sqlite3 table and call other functions."""
        logging.debug(f"Ingress {ip}")
        self.ips_scanned += 1
        is_up, latency = self.__ping(ip)
        if is_up:
            self.ips_latency.append((ip, latency))
            self.hosts_up += 1
            if self.single_scan is True: print("", file=self.file)
        else:
            self.ips_latency.append((ip, None))
            if self.ping_sweep: return
        if self.ping_scan: return
        connection = sqlite3.connect(self.database)
        c = connection.cursor()
        c.execute(f"DROP TABLE IF EXISTS IP_{ip.replace('.', '_')}")
        c.execute(f"CREATE TABLE IF NOT EXISTS IP_{ip.replace('.', '_')} (port INTEGER PRIMARY KEY, status STRING, service STRING, banner STRING)")
        
        for port in self.__class__.parse_port_str(self.port_str):
            self.__start_port_thread(ip, port)

        for thread in self.port_level_threads:
            thread.join()
        self.port_level_threads = []
        for port, status, banner in self.last_scan:
            #print(ip, port, status)
            try:
                try: service = socket.getservbyport(int(port))
                except: service = "unknown"
                c.execute(f"INSERT INTO IP_{ip.replace('.', '_')} (port, status, service, banner) VALUES ({int(port)}, '{status}', '{service}', '{banner}')")
                logging.debug(f"Adding {port}:{status} for {ip}")
            except sqlite3.IntegrityError as e:
                logging.warning(f"SQLite3 Integrity error {ip}:{port}:{status}")
        self.last_scan = []
        connection.commit()
        connection.close()
    
    @staticmethod
    def parse_port_str(port_str):
        """ Generator object to parse the port_str in these formats port-port,port,port """
        def validate_port(port):
            PORT_RANGE = (0, 65535)
            try: 
                port = int(port)
                assert port >= PORT_RANGE[0]
                assert port <= PORT_RANGE[1]
                return port
            except Exception as e:
                raise PinmapInputError(f"{port} is not correct") from e

        def subparse_port_str(port_str):
            if "-" in port_str:
                ports = port_str.split("-")
                if len(ports) > 2: 
                    raise PinmapInputError("The Port Addressess are not properly formatted")
                for port in range(int(ports[0]), int(ports[1])+1):
                    yield validate_port(port)
            else:
                yield validate_port(port_str.strip())
        
        if "," in port_str:
                for port_section in port_str.split(","):
                    for port in subparse_port_str(port_section):
                        yield port
        else:
            for port in subparse_port_str(port_str):
                yield port
    
    def __start_port_thread(self, ip, port):
        """ Pass the ip and port, validate port, start thread for that port """
        logging.debug("Ingress")
        # try: 
        #     port = int(port)
        #     if port >= self.PORT_RANGE[0] and port <= self.PORT_RANGE[1]:
        #         pass
        #     else:
        #         raise PinmapInputError("Port Failed Validation")
        # except:
        #     logging.info(f"Port {port} failed validation")
        #     return
        x = threading.Thread(target=self.__scan_port, args=(ip, port))
        x.start()
        time.sleep(random.randint(0, self.f_time))
        self.port_level_threads.append(x)

    def __scan_port(self, ip, port):
        """ Pass the ip and port, check what scan to do, append the results to the ongoing list """
        if self.scan_type == "SYN":
            status, banner = self.__class__.SYN_scan(ip, port)
        elif self.scan_type == "Banner":
            status, banner = self.__class__.banner_scan(ip, port)
        elif self.scan_type == "ACK":
            status, banner = self.__class__.ACK_scan(ip, port)
        elif self.scan_type == "XMAS":
             status, banner = self.__class__.custom_TCP_scan(ip, port, flag="FPU")
        elif self.scan_type == "FIN":
             status, banner = self.__class__.custom_TCP_scan(ip, port, flag="F")
        elif self.scan_type == "NULL":
             status, banner = self.__class__.custom_TCP_scan(ip, port, flag="")  
        elif self.scan_type == "UDP":
             status, banner = self.__class__.UDP_scan(ip, port)
        else:
            status, banner = self.__class__.basic_scan(ip, port)
        self.last_scan.append((port, status, banner))      
    
    def __ping(self, ip):
        if self.ping_method == "ICMP":
            return self.ICMP_ping(ip)
        elif self.ping_method == "ARP":
            return self.ARP_ping(ip)
        elif self.ping_method == "ACK":
            return self.ACK_ping(ip)
        elif self.ping_method == "SYN":
            return self.SYN_ping(ip)
        
    @staticmethod
    def ICMP_ping(ip):
        """ Pass the IP address to ping, return if it is up (bool) and latency (str) """
        start = datetime.now()
        ans, unans = sr(IP(dst=ip)/ICMP(), timeout=3, verbose=0, retry=1)
        result = len(ans)
        latency = datetime.now() - start
        return result, str(latency.seconds) + "." + str(latency.microseconds)[0-1] + "s"
    
    @staticmethod
    def ARP_ping(ip):
        """ Pass the IP address to ping, return if it is up (bool) and latency (str) """
        start = datetime.now()
        ans, unans = arping(ip, verbose=0, timeout=3)
        result = len(ans)
        latency = datetime.now() - start
        return result, str(latency.seconds) + "." + str(latency.microseconds)[0-1] + "s"

    @staticmethod
    def send_TCP(ip, port, flag):
        ans, unans = sr(IP(dst=ip)/TCP(dport=port,flags=flag), timeout=3, verbose=0)
        result = 0
        result_flag = ""
        for s, r in ans:
            if r.getlayer(TCP).flags == "SA":
                sr(IP(dst=ip)/TCP(dport=port,flags="R"), timeout=0, verbose=0)
            if s[TCP].dport == r[TCP].sport:
                result = len(ans)
                result_flag = r.getlayer(TCP).flags
        return result, str(result_flag) 
    
    @staticmethod
    def SYN_ping(ip, port=80):
        """ Pass the IP address to ping, return if it is up (bool) and latency (str) """
        start = datetime.now()
        result, x = __class__.send_TCP(ip, port, "S")
        latency = datetime.now() - start
        return result, str(latency.seconds) + "." + str(latency.microseconds)[0-1] + "s"
    
    @staticmethod
    def ACK_ping(ip, port=80):
        """ Pass the IP address to ping, return if it is up (bool) and latency (str) """
        start = datetime.now()
        result, x = __class__.send_TCP(ip, port, "A")
        latency = datetime.now() - start
        return result, str(latency.seconds) + "." + str(latency.microseconds)[0-1] + "s"
    
    @staticmethod
    def SYN_scan(ip, port):
        """ Pass the IP and port to scan, return status (str) and a blank string for compatability with banner grabbing """
        result, flag = __class__.send_TCP(ip, port, "S")
        if result == 1 and flag == "SA": status = "open"
        elif result == 1 and flag == "RST": status = "closed"
        elif result == 1 and "R" not in flag: status = "open"
        elif result == 0: status = "filtered"
        else: status = "closed"
        return (status, "")
    
    @staticmethod
    def UDP_scan(ip, port):
        """ Pass the IP and port to scan, return status (str) and a blank string for compatability with banner grabbing """
        ans,unans = sr(IP(dst=ip)/UDP(dport=[(port)]),inter=0.5,retry=1,timeout=1, verbose=0)
        time.sleep(2)
        status = "closed"
        try:
            if len(ans) == 0:
                status = "open|filtered"
            elif ans[0][1].getlayer(UDP) is None:
                status = "closed"
            else: 
                status = "open"
        except Exception as e:
            logging.debug(f"UDP: {e}: {ans}")
        return (status, "")
    
    @staticmethod
    def ACK_scan(ip, port):
        """ Pass the IP and port to scan, return status (str) and a blank string for compatability with banner grabbing """
        result, flag = __class__.send_TCP(ip, port, "A")
        if result == 1: status = "unfiltered"
        else: status = "filtered"
        return (status, "")
    
    @staticmethod
    def XMAS_scan(ip, port):
        """ Pass the IP and port to scan, return status (str) and a blank string for compatability with banner grabbing """
        result, flag = __class__.send_TCP(ip, port, "FPU")
        if result == 1: status = "open"
        else: status = "closed"
        return (status, "") 
    
    @staticmethod
    def custom_TCP_scan(ip, port, flag="F"):
        """ Pass the IP and port to scan, return status (str) and a blank string for compatability with banner grabbing """
        result, flag = __class__.send_TCP(ip, port, flag) # XMAS (FPU), Null and FIN (F)
        
        if result == 1 and flag == "RST": status = "closed"
        elif result == 0: status = "open|filtered"
        else: status = "closed"
        return (status, "") 
    
    @staticmethod
    def banner_scan(ip, port, return_str_length=50):
        """ Pass the IP and port to scan, return status (str) and a the banner (str) """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Set a timeout for the connection attempt
        banner = ''
        status = "closed"
        try:
            sock.connect((ip, port))
            status = "open"
            sock.send('WhoAreYou\r\n'.encode())
            banner = sock.recv(return_str_length).decode().strip()
            if banner is None or banner == "":
                banner = " "
            else:
                banner = re.sub(r"\s", "", banner)
        except: pass
        sock.close()
        return (status, banner)

    @staticmethod
    def basic_scan(ip, port):
        """ Pass the IP and port to scan, return status (str) and a blank string for compatability with banner grabbing """
        status = "closed"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            result = sock.connect_ex((ip, int(port)))
            if result == 0:
                status = "open"
        except socket.gaierror as e:
            pass
        except OSError as e:
            pass
        sock.close()
        return (status, "")
    
    def __end_pinmap(self, start_time):
        for thread in self.ip_level_threads:
            thread.join()
        for ip, latency in self.ips_latency:
            if latency is None:
                if self.single_scan is True or self.verbose:
                    print(f"Pinmap scan report for {ip}", file=self.file)
                    print(f"Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn", file=self.file)
                if self.ping_sweep: continue
            else:
                print(f"Pinmap scan report for {ip}", file=self.file)
                print(f"Host is up ({latency} latency).", file=self.file)
            if self.ping_scan: continue # No database if ping scan. 
            connection = sqlite3.connect(self.database)
            c = connection.cursor()
            rows = c.execute(f"SELECT * FROM IP_{ip.replace('.', '_')} ORDER BY port ASC")
            if self.scan_type != "Banner": print("PORT\tSTATE\tSERVICE", file=self.file)
            else: print("PORT\tSTATE\tSERVICE\tBANNER", file=self.file)
            for row in rows:
                if row[1] != "closed" or self.verbose:
                    print(f"{row[0]}\t{row[1]}\t{row[2]}\t{row[3]}", file=self.file)
            print("", file=self.file)
            connection.close()
        latency = datetime.now() - start_time
        latency = str(latency.seconds) + "." + str(latency.microseconds)[0-1] + "s"
        print(f"\nPinmap done: {self.ips_scanned} IP addresses ({self.hosts_up} hosts up) scanned in {latency} seconds", file=self.file)
        if self.json_filename: 
            json_obj = self.convert_to_json(self.database)
            with open(self.json_filename, "w") as f:
                f.write(json_obj)
        if self.delete_database and not self.ping_scan: self.remove_database()
        if self.silence_prints: sys.stdout = sys.__stdout__

    
    def remove_database(self):
        """ Delete self.database """
        try: os.remove(self.database)
        except FileNotFoundError: 
            logging.debug("Database not found")
            print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
    
    def convert_to_json(self, pinmap_database = "pinmap.sql"):
        """ Convert the provided database to json and return the json """
        logging.debug(f"Calling {__name__}")
        dicta = {}
        connection = sqlite3.connect(pinmap_database)
        c = connection.cursor()
        c.execute("SELECT name FROM sqlite_schema WHERE type ='table' AND name NOT LIKE 'sqlite_%';")
        tables = c.fetchall()
        for table in tables:
            sql_table = table[0]
            table = sql_table.replace("_", ".").replace("IP.", "")
            dicta[table] = {}
            for row in c.execute(f"SELECT * FROM {sql_table}"):
                dicta[table][row[0]] = {"status": row[1], "service": row[2], "banner": row[3]}
        json_obj = json.dumps(dicta)
        connection.close()
        return json_obj

## Example 1: Scans two ports on two IPs, banner grabs, and outputs to json file
# pmap = Pinmap("nmap  192.168.1.46,192.168.1.1 -p21-22 -sV -T5", json_filename="pinmap.json")

# # Example 2: Scans one ip, 23 ports, SYN scan
# pmap = Pinmap("nmap 192.168.1.1 -p 22-50 -sS")

## Example 3: Scans two ips, 4 ports, in verbose mode, gets json in variable
# pmap = Pinmap("nmap 192.168.1.1-192.168.1.2 -v -p 21-22,80,443", delete_database=False)
# pmap_json = pmap.convert_to_json()
# pmap.remove_database()
# print(pmap_json)

## Example 4: Ping scan
# pmap = Pinmap("192.168.1.1-192.168.1.2 -sn -PR -dd")

## Example 5: Scans a host in debug and outputs log to a file
# pmap = Pinmap("192.168.1.1 -dd", log_path="log.txt")

## Example 6: Saves the database and opens it
# pmap = Pinmap("192.168.1.1", delete_database=False, database="pinmap.sql")
# connection = sqlite3.connect("pinmap.sql")
# c = connection.cursor()
# c.execute("SELECT name FROM sqlite_schema WHERE type ='table' AND name NOT LIKE 'sqlite_%';")
# tables = c.fetchall()
# for table in tables:
#     print(f"Tablename {table[0]}:")
#     for row in c.execute(f"SELECT * FROM {table[0]}"):
#         print(row)
# connection.close()
# pmap.remove_database()

## Example 7: Manually checking one IP/ports responses
# ip = "192.168.1.1"
# port = 80
# print("ACK Ping:", Pinmap.ACK_ping(ip, port))
# print("SYN Ping:", Pinmap.SYN_ping(ip, port))
# print("ARP Ping:", Pinmap.ARP_ping(ip))
# print("ICMP Ping:", Pinmap.ICMP_ping(ip))
# print("---")
# print("ACK Scan:", Pinmap.ACK_scan(ip, port))
# print("SYN Scan:", Pinmap.SYN_scan(ip, port))
# print("XMAS Scan:", Pinmap.XMAS_scan(ip, port))
# print("Basic Scan:", Pinmap.basic_scan(ip, port))
# print("Banner Scan:", Pinmap.banner_scan(ip, port))

## Output all functions in Pinmap
# for key in Pinmap.__dict__.keys():
#     if "function" in str(Pinmap.__dict__[key]):
#         print(key)


# # Test Case 1: Parsing IP strings
# ips_correct = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
# ips_outputed = []
# for ip in Pinmap.parse_ip_str("192.168.1.1-192.168.1.3"):
#     ips_outputed.append(ip)
# if ips_correct == ips_outputed:
#     print("TC1: Pass")
# else: 
#     print(f"TC1: FAIL {ips_outputed}")


# # Test Case 2: Parsing IP strings
# ips_correct = ["192.168.1.1", "192.168.1.3"]
# ips_outputed = []
# for ip in Pinmap.parse_ip_str("192.168.1.1,192.168.1.3"):
#     ips_outputed.append(ip)
# if ips_correct == ips_outputed:
#     print("TC2: Pass")
# else: 
#     print(f"TC2: FAIL {ips_outputed}")

# # Test Case 3: Parsing IP strings
# ips_correct = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5', '192.168.1.6', '192.168.1.7', '192.168.1.8', '192.168.1.9', '192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13', '192.168.1.14', '192.168.1.15', '192.168.1.16', '192.168.1.17', '192.168.1.18', '192.168.1.19', '192.168.1.20', '192.168.1.21', '192.168.1.22', '192.168.1.23', '192.168.1.24', '192.168.1.25', '192.168.1.26', '192.168.1.27', '192.168.1.28', '192.168.1.29', '192.168.1.30', '192.168.1.31', '192.168.1.32', '192.168.1.33', '192.168.1.34', '192.168.1.35', '192.168.1.36', '192.168.1.37', '192.168.1.38', '192.168.1.39', '192.168.1.40', '192.168.1.41', '192.168.1.42', '192.168.1.43', '192.168.1.44', '192.168.1.45', '192.168.1.46', '192.168.1.47', '192.168.1.48', '192.168.1.49', '192.168.1.50', '192.168.1.51', '192.168.1.52', '192.168.1.53', '192.168.1.54', '192.168.1.55', '192.168.1.56', '192.168.1.57', '192.168.1.58', '192.168.1.59', '192.168.1.60', '192.168.1.61', '192.168.1.62', '192.168.1.63', '192.168.1.64', '192.168.1.65', '192.168.1.66', '192.168.1.67', '192.168.1.68', '192.168.1.69', '192.168.1.70', '192.168.1.71', '192.168.1.72', '192.168.1.73', '192.168.1.74', '192.168.1.75', '192.168.1.76', '192.168.1.77', '192.168.1.78', '192.168.1.79', '192.168.1.80', '192.168.1.81', '192.168.1.82', '192.168.1.83', '192.168.1.84', '192.168.1.85', '192.168.1.86', '192.168.1.87', '192.168.1.88', '192.168.1.89', '192.168.1.90', '192.168.1.91', '192.168.1.92', '192.168.1.93', '192.168.1.94', '192.168.1.95', '192.168.1.96', '192.168.1.97', '192.168.1.98', '192.168.1.99', '192.168.1.100', '192.168.1.101', '192.168.1.102', '192.168.1.103', '192.168.1.104', '192.168.1.105', '192.168.1.106', '192.168.1.107', '192.168.1.108', '192.168.1.109', '192.168.1.110', '192.168.1.111', '192.168.1.112', '192.168.1.113', '192.168.1.114', '192.168.1.115', '192.168.1.116', '192.168.1.117', '192.168.1.118', '192.168.1.119', '192.168.1.120', '192.168.1.121', '192.168.1.122', '192.168.1.123', '192.168.1.124', '192.168.1.125', '192.168.1.126', '192.168.1.127', '192.168.1.128', '192.168.1.129', '192.168.1.130', '192.168.1.131', '192.168.1.132', '192.168.1.133', '192.168.1.134', '192.168.1.135', '192.168.1.136', '192.168.1.137', '192.168.1.138', '192.168.1.139', '192.168.1.140', '192.168.1.141', '192.168.1.142', '192.168.1.143', '192.168.1.144', '192.168.1.145', '192.168.1.146', '192.168.1.147', '192.168.1.148', '192.168.1.149', '192.168.1.150', '192.168.1.151', '192.168.1.152', '192.168.1.153', '192.168.1.154', '192.168.1.155', '192.168.1.156', '192.168.1.157', '192.168.1.158', '192.168.1.159', '192.168.1.160', '192.168.1.161', '192.168.1.162', '192.168.1.163', '192.168.1.164', '192.168.1.165', '192.168.1.166', '192.168.1.167', '192.168.1.168', '192.168.1.169', '192.168.1.170', '192.168.1.171', '192.168.1.172', '192.168.1.173', '192.168.1.174', '192.168.1.175', '192.168.1.176', '192.168.1.177', '192.168.1.178', '192.168.1.179', '192.168.1.180', '192.168.1.181', '192.168.1.182', '192.168.1.183', '192.168.1.184', '192.168.1.185', '192.168.1.186', '192.168.1.187', '192.168.1.188', '192.168.1.189', '192.168.1.190', '192.168.1.191', '192.168.1.192', '192.168.1.193', '192.168.1.194', '192.168.1.195', '192.168.1.196', '192.168.1.197', '192.168.1.198', '192.168.1.199', '192.168.1.200', '192.168.1.201', '192.168.1.202', '192.168.1.203', '192.168.1.204', '192.168.1.205', '192.168.1.206', '192.168.1.207', '192.168.1.208', '192.168.1.209', '192.168.1.210', '192.168.1.211', '192.168.1.212', '192.168.1.213', '192.168.1.214', '192.168.1.215', '192.168.1.216', '192.168.1.217', '192.168.1.218', '192.168.1.219', '192.168.1.220', '192.168.1.221', '192.168.1.222', '192.168.1.223', '192.168.1.224', '192.168.1.225', '192.168.1.226', '192.168.1.227', '192.168.1.228', '192.168.1.229', '192.168.1.230', '192.168.1.231', '192.168.1.232', '192.168.1.233', '192.168.1.234', '192.168.1.235', '192.168.1.236', '192.168.1.237', '192.168.1.238', '192.168.1.239', '192.168.1.240', '192.168.1.241', '192.168.1.242', '192.168.1.243', '192.168.1.244', '192.168.1.245', '192.168.1.246', '192.168.1.247', '192.168.1.248', '192.168.1.249', '192.168.1.250', '192.168.1.251', '192.168.1.252', '192.168.1.253', '192.168.1.254']
# ips_outputed = []
# for ip in Pinmap.parse_ip_str("192.168.1.1/24"):
#     ips_outputed.append(ip)
# if ips_correct == ips_outputed:
#     print("TC3: Pass")
# else: 
#     print(f"TC3: FAIL {ips_outputed}")


# # Test Case 4: Parsing port strings
# ports_correct = [22, 23, 24, 25]
# ports_outputed = []
# for port in Pinmap.parse_port_str("22-24,25"):
#     ports_outputed.append(port)
# if ports_correct == ports_outputed:
#     print("TC4: Pass")
# else: 
#     print(f"TC4: FAIL {ports_outputed}")


