import socket
import logging 
import ipaddress
import sqlite3
import re
import threading
import subprocess # To Remove
from datetime import datetime
import time
import random
import os
import json
import sys

import requests # To Remove
from scapy.all import IP, ICMP, sr1, TCP, UDP # To Remove UDP

# TO DO: 
# -sU: Perform a UDP scan.
# Add output as xml? 

# Layout:
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
    Pinmap("-p 20-22,80,443 192.168.1.1")
    Pinmap("-T5 192.168.1.1/24")
    Pinmap("-Pn 192.168.1.1-192.168.2.3", database = "pinmap.sql", delete_database=False, json_filename='pinmap.json')

    Differences from nmap:
    Nmap defaults to the top 1000 ports, Pinmap to the top like 100
    Nmap defaults to SYN, Pinmap to basic_scan 
    Nmap has several flags and features (scripts) without support in Pinmap
    Nmap has some functionality (convert to json) not in Pinmap 
    Nmap -sV does something other than banner grabbing, but Pinmap does banner grabbing for that
    """
    NMAP_HELP = """ """ # TO ADD
    PORT_RANGE = (0, 65535)
    ips_to_scan = []
    ports_to_scan = []
    f_time = 0 # Speed, lower is faster
    port_str = "20-23,25,53,67-68,69,80,110,119,123,137-139,143,161-162,179,194,389,443,445,465,514-515,587,636,993-995,1080,1433-1434,1701,1723,3306,3389,5060,5222,5269,5432,5900-5901,8080,8443,9100,9200,11211,27017"
    ping_sweep = True # Ping before scanning ports
    ping_scan = False # Only ping, no port scans
    single_scan = False # Scanning one IP
    verbose = False # Verbosity level, -v or -vv
    ips_scanned = 0 # Count
    hosts_up = 0 # Count
    port_level_threads = []
    ip_level_threads = [] # Depreciated since this caused a race condition with sqlite... Whoops
    last_scan = [] 
    ips_latency = []
    scan_type = "basic"
    debug_level = 0

    def __init__(self, input_str, database = "pinmap.sql", delete_database=True, file=None, json_filename=False, silence_prints=False, log_path=False):
        """ Arguments:
        input_str (type=str) - the nmap command
        database (type=str) - the sqlite3 database to put each ip table in (default: pinmap.sql)
        delete_database (type=bool) - whether or not to delete the database when done (default: True)
        file (type=fileobj) - a writable file object to print the output to (default: None)
        json_filename (type=str) - will write the scan results in json to path (default: False)
        silence_prints(type=bool) - will silence all print statements (not errors) (default: False)
        log_path(type=str) - will write log to that path if provided. Consider -d or -dd if using this (default: False)
        
        Currently input_str has support for:
            -T = Time 0(slowest) to 5(fastest) 
            -p = Port numbers
            -pn = Scan ports even if fail ping
            -sS = SYN Scan
            -sV = Get Version Info (Banner scan)
            -v = Verbose
            -d/-dd = Increase debug level
            -sn = Ping scan only
        """
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
            elif re.match(r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}", part):
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
        
        # set single_scan then start
        if len(ips) == 1 and "/" not in ips[0] and "," not in ips[0] and "-" not in ips[0]:
            self.single_scan = True
        self.__start_pinmap(",".join(ips))
    
    @staticmethod
    def ping(ip):
        """ Pass the IP address to ping, return if it is up (bool) and latency (str) """
        start = datetime.now()
        ping = IP(dst=ip)/ICMP()
        res = sr1(ping,timeout=1,verbose=0)
        if res == None:
            result = False
        else:
            result = True
        latency = datetime.now() - start
        return result, str(latency.seconds) + "." + str(latency.microseconds)[0-1] + "s"

    @staticmethod
    def SYN_scan(ip, port):
        """ Pass the IP and port to scan, return status (str) and a blank string for compatability with banner grabbing """
        status = "closed"
        tcpRequest = IP(dst=ip)/TCP(dport=port,flags="S")
        tcpResponse = sr1(tcpRequest,timeout=1,verbose=0)
        try:
            if tcpResponse.getlayer(TCP).flags == "SA":
                status = "open"
        except AttributeError:
            pass
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
        
    def __scan_port(self, ip, port):
        """ Pass the ip and port, check what scan to do, append the results to the ongoing list """
        if self.scan_type == "SYN":
            status, banner = self.__class__.SYN_scan(ip, port)
        elif self.scan_type == "Banner":
            status, banner = self.__class__.banner_scan(ip, port)
        else:
            status, banner = self.__class__.basic_scan(ip, port)
        self.last_scan.append((port, status, banner))      
    
    def __start_port_thread(self, ip, port):
        """ Pass the ip and port, validate port, start thread for that port """
        logging.debug("Ingress")
        try: 
            port = int(port)
            if port >= self.PORT_RANGE[0] and port <= self.PORT_RANGE[1]:
                pass
            else:
                raise PinmapInputError("Port Failed Validation")
        except:
            logging.info(f"Port {port} failed validation")
            return
        x = threading.Thread(target=self.__scan_port, args=(ip, port))
        x.start()
        time.sleep(random.randint(0, self.f_time))
        self.port_level_threads.append(x)
    
    def __parse_port_str(self, ip, port_str):
        """ Pass the ip and port_str. Parse port_str and call __start_port_thread """
        if "," in port_str:
            for port in port_str.split(","):
                self.__parse_port_str(ip, port)
        elif "-" in port_str:
            ports = port_str.split("-")
            if len(ports) > 2: 
                raise PinmapInputError("The Port Addressess are not properly formatted")
            for port in range(int(ports[0]), int(ports[1])+1):
                self.__start_port_thread(ip, port)       
        else:
            self.__start_port_thread(ip, port_str)

    def __make_ip_table(self, ip, port_str):
        """ Pass ip and port_str. Make sqlite3 table and call other functions."""
        logging.debug(f"Ingress {ip}")
        self.ips_scanned += 1
        is_up, latency = self.__class__.ping(ip)
        if is_up is True:
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
        x = self.__parse_port_str(ip, port_str)
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
        return x

    def __start_ip_thread(self, *args, **kwargs):
        """ Now a pass through due to race condition. Call __make_ip_table """
        logging.debug("Ingress")
        # x = threading.Thread(target=self.__scan_ports_wrapper, args=args)
        # x.start()
        # self.ip_level_threads.append(x)
        self.__make_ip_table(*args, **kwargs) 
        # Did not do threading due to sqlite error database locked

    def __parse_ip_str(self, ip_str, port_str):
        """ Pass ip_str and port_str, parse ip_str """
        logging.debug("Ingress")
        if "-" in ip_str:
            ips = ip_str.split("-")
            if len(ips) > 2: 
                raise PinmapInputError("The IP Addressess are not properly formatted")
            for ip in range(int(ipaddress.ip_address(ips[0])), int(ipaddress.ip_address(ips[1]))+1):
                self.__start_ip_thread(str(ipaddress.ip_address(ip)), port_str)
        elif "/" in ip_str:
            for ip in ipaddress.ip_network(ip_str, False).hosts():
                self.__start_ip_thread(str(ipaddress.ip_address(ip)), port_str)
        else:
            self.__start_ip_thread(ip_str, port_str)

    def __start_pinmap(self, ip_str):
        """Start timer, start parseing ip_str, print output"""
        logging.debug("Ingress")
        start = datetime.now()
        logging.info(f"ip_str = '{ip_str}'")
        port_str = self.port_str
        logging.info(f"port_str = '{port_str}'")
        if port_str == "": 
            raise PinmapInputError("Port_str cannot be blank")
        if "," in ip_str:
            for ip in ip_str.split(","):
                self.__parse_ip_str(ip, port_str)
        else:
            self.__parse_ip_str(ip_str, port_str)

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
        latency = datetime.now() - start
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
        os.remove(self.database)
    
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


# Example 1: Scans two ports on two IPs, banner grabs, and outputs to json file
# pmap = Pinmap("nmap  192.168.1.46,192.168.1.1 -p21-22 -sV -T5", json_filename="pinmap.json")

# Example 2: Scans one ip, 23 ports, SYN scan
# pmap = Pinmap("nmap 192.168.1.1 -p 22-50 -sS")

# Example 3: Scans two ips, 4 ports, in verbose mode, gets json in variable
# pmap = Pinmap("nmap 192.168.1.1-192.168.1.2 -v -p 21-22,80,443", delete_database=False)
# pmap_json = pmap.convert_to_json()
# pmap.delete_database()
# print(pmap_json)

# Example 4: Ping scans all ports on localhost
pmap = Pinmap("192.168.1.1-192.168.1.2 -sn")

# Example 5: Scans a host in debug and outputs log to a file
# pmap = Pinmap("192.168.1.1 -dd", log_path="log.txt")

# Example 6: Saves the database and opens it
# pmap = Pinmap("192.168.1.1", delete_database=False, database="pinmap.sql")
# connection = sqlite3.connect("pinmap.sql")
# c = connection.cursor()
# c.execute("SELECT name FROM sqlite_schema WHERE type ='table' AND name NOT LIKE 'sqlite_%';")
# tables = c.fetchall()
# for table in tables:
#     print(f"Tablename {table}:")
#     for row in c.execute(f"SELECT * FROM {table}"):
#         print(row)


# Output all functions in Pinmap
# for key in Pinmap.__dict__.keys():
#     if "function" in str(Pinmap.__dict__[key]):
#         print(key)


