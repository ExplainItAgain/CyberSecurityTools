"""A GUI assistant for a security operations center. 
Contains several useful programs and references."""

import re
import os
import difflib
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
import _tkinter
import time
import logging
import configparser
from io import StringIO
import json
import ast
import socket
import subprocess

# Is it really third party?
try:
    import requests
except ImportError as e:
    logging.warning("Requests could not be imported. Run 'pip3 install requests' to fix")

from URLdecoder import decode as URL_decode
from phish_reel import send_email, get_email_options
from pinmap import Pinmap
from r7_tools import InsightVM
from s1_tools import SentinelOne


FORMAT = "%(asctime)s: %(levelname)s: %(message)s (File %(filename)s: Function %(funcName)s: Line %(lineno)d)"

logging.basicConfig(level=logging.INFO, format=FORMAT, datefmt='%H:%M:%S')



# This is for vscode which does not run from the directory of the file like a twit.
# This program uses relative file paths.
os.chdir(os.path.dirname(__file__))

# TO ADD:
### New window tab?
### About tab?
### add tests? 
### Fix the font for powershell sandbox
### Add python sandbox. 
# MAYBE: 
### email header parser
### Base64 decoder/encoder

class CustomText(tk.Text):
    '''A text widget with a new method, highlight_pattern()

    Example:
    text = CustomText()
    text.tag_configure("red", foreground="#ff0000")
    text.highlight_pattern("this should be red", "red")

    The highlight_pattern method is a simplified python
    version of the tcl code at http://wiki.tcl.tk/3246
    '''
    def __init__(self, *args, **kwargs):
        tk.Text.__init__(self, *args, **kwargs)

    def highlight_pattern(self, pattern, tag, start="1.0", end="end",
                          regexp=False):
        '''Apply the given tag to all text that matches the given pattern

        If 'regexp' is set to True, pattern will be treated as a regular
        expression according to Tcl's regular expression syntax.
        '''

        start = self.index(start)
        end = self.index(end)
        self.mark_set("matchStart", start)
        self.mark_set("matchEnd", start)
        self.mark_set("searchLimit", end)

        count = tk.IntVar()
        while True:
            index = self.search(pattern, "matchEnd","searchLimit",
                                count=count, regexp=regexp)
            if index == "": break
            if count.get() == 0: break # degenerate pattern which matches zero-length strings
            self.mark_set("matchStart", index)
            self.mark_set("matchEnd", "%s+%sc" % (index, count.get()))
            self.tag_add(tag, "matchStart", "matchEnd")

class SOCer:
    """Main Class for SOCer GUI"""
    keys = [
            # {"section": "", "key_name": "", "default": ""},
            # {"section": "", "key_name": "", "default": ""},
            # {"section": "", "key_name": "", "default": ""},
            {"section": "HOTKEYS", "key_name": "<f1>", "default": ""},
            {"section": "VT", "key_name": "virus_total_key", "default": ""},
            {"section": "url_scan", "key_name": "url_scan_key", "default": ""},
            {"section": "R7", "key_name": "insightvm_key", "default": "[base64 encoded username and password]"},
            {"section": "R7", "key_name": "base_url", "default": "https://insightvmserver.local:3780"},
            {"section": "S1", "key_name": "sentinelone_key", "default": ""},
            {"section": "S1", "key_name": "base_url", "default": "https://usxx1-xxxx.sentinelone.net"}        
            ]
    def __init__(self):
        self.frames = []
        self.vars = []
        self.window = tk.Tk()
        self.window.title("SOCer")
        #self.window.tk.call('wm', 'iconphoto', self.window._w, tk.PhotoImage(file='SOCer.png'))
        
        # main menu creation
        main_menu = tk.Menu(self.window)
        self.window.config(menu=main_menu)

        # 1nd main menu item: a simple callback
        # def about_app():
        #     messagebox.showinfo(title="About", message="Author: ExplainItAgain")
        main_menu.add_command(label="About", command=lambda: self.standard_window(self.about_window, "About"))
        
        # 2st main menu item: an empty (as far) submenu
        util_menu = tk.Menu(main_menu)
        main_menu.add_cascade(label="Util", menu=util_menu, underline=0)

        tabs = [
            # {"name":"", "command": self.},
            # {"name":"", "command": self.},
            {"name":"Add Credentials", "command": self.add_credentials},
            {"name":"Troubleshooting", "command": self.troubleshooting},
            ]
        tabs.sort(key=lambda x: x["name"])
        for tab in tabs: 
            util_menu.add_command(label=tab["name"], command=lambda tab=tab: self.standard_window(tab["command"], tab["name"]), underline=0)
        
        # 3rd main menu item
        program_menu = tk.Menu(main_menu)
        main_menu.add_cascade(label="Apps", menu=program_menu, underline=0)

        tabs = [
            # {"name":"", "command": self.},
            # {"name":"", "command": self.},
            {"name":"PiNmap 1.0", "command": self.pinmap},
            {"name":"PhishReel 1.0", "command": self.phish_reel},
            {"name":"API Query 1.0", "command": self.api_query},
            {"name":"IP Dig 2.0", "command": self.ip_dig},
            {"name":"LinkCheck 1.0", "command": self.link_checker}, 
            {"name":"R7 Delete Assets 1.0", "command": self.ivm_delete_assets},
            {"name":"Mass IP Check 1.0", "command": self.mass_ip}
            ]
        tabs.sort(key=lambda x: x["name"])
        for tab in tabs: 
            program_menu.add_command(label=tab["name"], command=lambda tab=tab: self.standard_window(tab["command"], tab["name"]), underline=0)


        # 4th main menu item
        tool_menu = tk.Menu(main_menu)
        main_menu.add_cascade(label="Tools", menu=tool_menu, underline=0)

        tabs = [
            {"name":"ClipBoard Combiner 1.0", "command": self.combiner},
            {"name":"Find&Replace 1.0", "command": self.replacer},
            {"name":"Comparer 1.0", "command": self.comparer},
            {"name":"Comparer 2.0", "command": self.comparer2},
            {"name":"Black Screen 1.0", "command": self.black_screen},
            {"name":"Hot Keys 1.0", "command": self.hot_keys},
            {"name":"Paste+ 1.0", "command": self.paste_plus} #,
            # {"name":"", "command": self.},
            # {"name":"", "command": self.}
            ]
        tabs.sort(key=lambda x: x["name"])
        for tab in tabs: 
            tool_menu.add_command(label=tab["name"], command=lambda tab=tab: self.standard_window(tab["command"], tab["name"]), underline=0)

        # 5th main menu item
        tool_menu = tk.Menu(main_menu)
        main_menu.add_cascade(label="Adv", menu=tool_menu, underline=0)

        tabs = [
            # {"name":"", "command": self.},
            # {"name":"", "command": self.},
            # {"name":"", "command": self.},
            {"name":"Powershell", "command": self.powershell_tab}
            ]
        tabs.sort(key=lambda x: x["name"])
        for tab in tabs: 
            tool_menu.add_command(label=tab["name"], command=lambda tab=tab: self.standard_window(tab["command"], tab["name"]), underline=0)


        # 6th Menu Item
        reference_files = os.listdir("./reference")
        
        reference_menu = tk.Menu(main_menu)
        main_menu.add_cascade(label="Ref", menu=reference_menu, underline=0)

        for file in reference_files:
            reference_menu.add_command(label=file, command=lambda file=file: self.standard_window(self.ref_tab, "Reference Files", "reference/" + file), underline=0)

        # 7th Menu Item 
        # def new_window():
        #     # th1 = threading.Thread(target=SOCer)
        #     # th1.start()
        #     subprocess.call(["python3", "SOCer.py"])
        # main_menu.add_command(label="New Tab", command=new_window)

        # 8th Menu Item 
        def refresh_window():
            self.window.destroy()
            SOCer()
        main_menu.add_command(label="Refresh Window", command=refresh_window)

        self.update_creds()

        #self.welcome_window()
        self.standard_window(self.welcome_window, "Welcome")

        self.load_hot_keys()
        
        self.window.mainloop()
        logging.info("SOCer Initiated")

    def about_window(self, frame):
        welcome_text = """ Getting Started: I'd recommend adding python and SOCer to path.

        Contents:

        Util
        - Add Credentials - Some of the Apps require API keys and base-urls for certain features, 
            indicated by a *
        
        Apps
        - API Query - This is a basic api client
        - IP Dig* - Provides some basic ip/hostname resolution and information
        - LinkCheck* - Provides some unwrapping and reputation checks
        - PhishReel* - Allows you to send emails via SNMP, you will need to set up its config file
        - PiNmap - Similiar to nmap, and many of the same commands work
        - R7 Delete Assets 1.0* - Remove assets in bulk from InsightVM if you have it
        
        Tools
        - Black Screen - Opens up a all-black window so it appears your computer is off
        - ClipBoard Combiner - Press go, copy a few things, it combines everything you copied
        - Comparer - Compare two texts for differences
        - Find&Replace - What it sounds like, but includes support for Regex
        - Hot Keys - You can set hot keys to copy certain commonly used values
        - Paste+ - You paste something and it will type it for you for times when pasting is not allowed
       
        Reference
        - This is for commonly used reference files, but it is editable
        
        Note:
        This is meant to perform many functions adequately, but some of these functions are better
        done with specific tools such as nmap, Notepad++, and Burp Suite. Many do not have common 
        conterparts and no other application I know of supports them all.
        """
        self.standard_label(frame[0], text=welcome_text, justify="left")
    
    def destroy_frames(self):
        for frame in self.frames:
            frame.destroy()
        for var in self.vars:
            del var

    def get_config_file(self):
        config = configparser.ConfigParser()
        # if os.path.isfile("localonly.SOCer.config"):
        #     config.read("localonly.SOCer.config")
        # else:
        config.read("SOCer.config")
        return config
    
    def save_config_file(self, config):
        # if os.path.isfile("localonly.SOCer.config"):
        #     with open("localonly.SOCer.config", "w") as f: 
        #         config.write(f)
        # else:
        with open("SOCer.config", "w") as f: 
            config.write(f)

    def load_hot_keys(self):
        config = self.get_config_file()
        for key in config["HOTKEYS"].keys():
            self.window.bind(key.upper(), lambda x: self.copy_from_hot_key(key, config["HOTKEYS"][key]))

    
    def standard_input_oneliner(self, frame, text=None, textvariable=None, row=0, column=0, columnspan=1, width=95,l_background="white", e_background="lightgrey", across=True):
        if text is not None: 
            self.standard_label(frame, text=text, background=l_background, row=row, column=column, columnspan=columnspan)
            if across: column += 1
            else: row += 1
        temp_entry = tk.Entry(frame, background=e_background, textvariable=textvariable, width=width, font=("Arial",11,))#, height=5)
        temp_entry.grid(row=row, column = column, columnspan=columnspan)

    def standard_button(self, frame, text, command, row=0, column=0, columnspan=1, rowspan=1, width=20, height=1):
        temp_button = tk.Button(frame, text=text, command=command, background="slategray1", activebackground="blue", width=width, height=height, font=("@Yu Gothic UI Semilight",10, 'bold'))
        temp_button.grid(row=row, column=column, columnspan=columnspan, rowspan=rowspan)

    def standard_radio_buttons(self, frame, label_text, texts_values: list[list], variable, row=0, column=0, seperate_label_line=0, no_label=0):
            if not no_label:
                self.standard_label(frame, text=label_text, row=row, column=column)
            if seperate_label_line:
                row += 1
            if not seperate_label_line and not no_label:
                column += 1
            for switch_list in texts_values:
                radio_switch = tk.Radiobutton(frame, text = switch_list[0], variable = variable, 
                                                value = switch_list[1], font=("Arial",11,), background= "white")
                radio_switch.grid(row=row, column=column)
                column += 1      
    def standard_textbox(self, frame, label_text=None, row=0, column=0, columnspan = 1, height=5, width=80,l_background="white", t_background="lightgrey"):
        if label_text is not None:
            self.standard_label(frame, text=label_text, background=l_background, row=row, column=column, columnspan=columnspan)
            row += 1
        temp_text = CustomText(frame, background=t_background, height=height, width=width, font=("Arial",11,)) # "@Yu Gothic UI Semilight",10
        temp_text.grid(row=row, column=column, columnspan=columnspan)  
        return temp_text
    
    def standard_label(self, frame, text=None, textvariable=None, justify='center', background="white", row=0, column=0, columnspan=1, padx=0, pady=0, width=None):
        label = tk.Label(frame, text=text, textvariable=textvariable, justify=justify, background=background, width=width, font=("@Yu Gothic UI Semilight",9))
        label.grid(row=row, column=column, padx=padx, pady=pady, columnspan=columnspan)
        
    def standard_frame(self, frame, bg='white', text=None, font=("@Yu Gothic UI Semibold",9), row=0, column=0):
        frame = tk.LabelFrame(frame, text=text, bg=bg, font=font)
        frame.grid(row=row, column=column)
        return frame
    
    
    def standard_window(self, function, label="", *args):
        self.destroy_frames()
        label_frame_1 = self.standard_frame(self.window, text=label, bg='white', font=("@Yu Gothic UI Semibold",9)) # Bookman Old Style
        label_frame_2 = self.standard_frame(self.window, bg='white', row=1)
        label_frame_3 = self.standard_frame(self.window, bg='white', row=2)
        label_frame_4 = self.standard_frame(self.window, bg='white', row=3)
        label_frame_5 = self.standard_frame(self.window, bg='white', row=4)
        self.frames = [label_frame_1, label_frame_2, label_frame_3, label_frame_4, label_frame_5]
        logging.info(f"Calling {function} with {self.frames, *args}")
        function(self.frames, *args)

    def standard_options_menu(self, frame, variable, labeltext=None, row=0, column=0, options=[]):
        if labeltext is not None:
            self.standard_label(frame, text=labeltext, row=row, column=column)
            column +=1
        option_menu = tk.OptionMenu(frame, variable, *options)
        option_menu.grid(row=row, column=column)

    def standard_checkbuttons(self, frame, text_vars = [], across=True, row=0, column=0):
        for text_var in text_vars:
            chckb = tk.Checkbutton(frame, text=text_var[0], variable=text_var[1], font=("Arial",11,))
            chckb.grid(row=row, column=column)
            if across: column += 1
            else: row += 1

    def welcome_window(self, frame):
        welcome_text = """ Welcome to SOCer! Look at the above tabs to explore!"""
        self.standard_label(frame[0], text=welcome_text, justify="left", padx=50, pady=50)
        
    def ref_tab(self, frame, file):
        file_path = tk.StringVar()
        file_path.set(file)

        def save_file():
            with open(file_path.get(), "w") as f:
                f.write(text_box.get("1.0", tk.END))
        
        self.standard_input_oneliner(frame[0], "File:", file_path)
        text_box = self.standard_textbox(frame[1], "", height=20)
        with open(file, "r") as f:
            text_box.insert("1.0", f.read())

        self.standard_button(frame[2], text="Save", command=save_file)

    def mass_ip(self, frame):
        def find_in_grid(frame, row, column):
            for child in frame.children.values():
                info = child.grid_info()
                if info['row'] == row and info['column'] == column:
                    return child
                
        def make_cells(height, width, frame, values=None):
            spreadsheet = []
            if values is None: values = ["" for x in range(height*width)]
            for i in range(height): #Rows
                spreadsheet.append([])
                for j in range(width): #Columns
                    temp_var = tk.StringVar()
                    self.vars.append(temp_var)
                    spreadsheet[i].append(temp_var)
                    temp_var.set(values[0])
                    tk.Entry(frame, textvariable=temp_var).grid(row=i, column=j)
                    values.pop(0)
            return spreadsheet
        
        make_cells(1, 4, frame[0], values=["IP", "Org", "Country", "Site"])
        spreadsheet = make_cells(20, 4, frame[1])
                    
        def set_cell(row=0, column=0, value = "", spreadsheet=spreadsheet):
            spreadsheet[row][column].set(value)

        def paste_ips():
            ips = self.window.clipboard_get()
            ips = re.split(r"\s", ips)
            for ip_ind in range(len(ips)):
                set_cell(ip_ind, 0, ips[ip_ind])

        def run_ip_info():
            for row_index in range(len(spreadsheet)):
                 if spreadsheet[row_index][1].get().strip() != "" or len(spreadsheet[row_index][0].get()) < 7: 
                    continue
                 ret_text, ret_dict = self.run_ipinfo(spreadsheet[row_index][0].get())
                 if ret_dict is None:
                     pass
                 else:
                    for columns in zip([1, 2, 3], ["org", "country", "hostname"]):
                        try:
                            spreadsheet[row_index][columns[0]].set(ret_dict[columns[1]])
                            # spreadsheet[row_index][2].set(ret_dict["country"])
                            # spreadsheet[row_index][3].set(ret_dict["hostname"])
                        except Exception as e:
                            logging.error(e)
                            logging.error(ret_text)

        def copy_all():
            ret_string = ""
            for row_index in range(len(spreadsheet)):
                for column_index in range(len(spreadsheet[row_index])):
                    ret_string += spreadsheet[row_index][column_index].get() + "\t"
                ret_string += "\n"
            self.window.clipboard_append(ret_string)

          
        self.standard_button(frame[2], text="Paste IPs", command=paste_ips)
        self.standard_button(frame[2], text="Run ipinfo.io", command=run_ip_info, column=1)
        self.standard_button(frame[2], text="Copy All", command=copy_all, column=2)

    def run_ps(self, cmd):
        completed = subprocess.run(["powershell", "-Command", cmd], capture_output=True)
        return completed
    
    def powershell_tab(self, frame):
        cmd = """function dotask {
            param (
                $keylist, # A list of keys to type
                $window, # A windowname to activate
                $sleep # Time to sleep before typing
            )
            $wshell = New-Object -ComObject wscript.shell;
            if ($window -eq "") {
                #nothing
                }
            else {
                $wshell.AppActivate($window)
                }
            Sleep -seconds $sleep

            foreach ($key in $keylist) {
                $wshell.SendKeys($key)
                }
        }
        # Keep Your Computer Awake
        $hours = 1
        $minutes = 60*$hours
        for ($i=0; $i -lt $minutes;$i++) {
            dotask -keylist @("%") -window "" -sleep 60
        }"""
        def run_script():
            output_text.delete("1.0", tk.END)
            res = self.run_ps(text_box.get("1.0", tk.END))
            res = str(res).replace("\\n", "\n") # TO DO. This output is crap. Is it the Font? 
            output_text.insert("1.0", res)
        text_box = self.standard_textbox(frame[0], height=10)
        text_box.insert("1.0", cmd)
        output_text = self.standard_textbox(frame[1], label_text="output", row=2)
        self.standard_button(frame[2], text="run", command=run_script)
    
    def paste_plus(self, frame):
        seconds = tk.StringVar()
        seconds.set(5)
        value = tk.StringVar()
        def send_keys():
            self.run_ps(f'start-sleep -seconds {seconds.get()}; $wshell = New-Object -ComObject Wscript.Shell;$wshell.sendkeys("{value.get()}")')
        self.standard_input_oneliner(frame[0], "Value to Paste", value)
        self.standard_input_oneliner(frame[0], "Second to Wait", seconds, row=1)
        self.standard_button(frame[1], text="Run", command=send_keys)

    def troubleshooting(self, frame):
        # Add tests? 
        def check():
            # Check Config Keys
            config = self.get_config_file()
            for key in self.keys:
                temp = config[key["section"]][key["key_name"]]
                if temp == key["default"]:
                    results.insert("1.0", f'Check config key: [{key["section"]}][{key["key_name"]}]')
            # Check Powershell Config
            cmd = """write-host test"""
            res = self.run_ps(cmd)
            if res.returncode != 0:
                results.insert("1.0", f'Powershell connection failed. Do you have powershell?')

        results = self.standard_textbox(frame[0], label_text="Results")
        self.standard_button(frame[1], text="Run", command=check)

    def update_creds(self):
        config = self.get_config_file()
        for key in self.keys:
            try:
                temp = config[key["section"]][key["key_name"]]
            except KeyError:
                try: 
                    config[key["section"]][key["key_name"]] = key["default"]
                except KeyError: 
                    config.add_section(key["section"])
                    config[key["section"]][key["key_name"]] = key["default"]
        self.save_config_file(config)

    def add_credentials(self, frame):
        key_vars = []
        config = self.get_config_file()
        for key in self.keys:
            temp = tk.StringVar()
            temp.set(config[key["section"]][key["key_name"]])
            key_vars.append(temp)
        for index in range(len(key_vars)):
            self.standard_input_oneliner(frame[0], text=f"{self.keys[index]['section']} {self.keys[index]['key_name']}", textvariable=key_vars[index], row=index)

        def save_all():
            nonlocal config
            for index in range(len(key_vars)):
                config[self.keys[index]["section"]][self.keys[index]["key_name"]] = key_vars[index].get()
            self.save_config_file(config=config)

        self.standard_button(frame[1], text="Save", command=save_all)
        
    def ivm_delete_assets(self, frame):
        def delete_assets():
            output_txbox.delete("1.0", tk.END)
            assets = re.split("[\s;:,]", asset_txbox.get("1.0", tk.END))
            for asset in assets:
                ids = InsightVM.remove_asset(asset)
                output_txbox.insert(tk.END, f"{asset} : Results {str(list(ids))}")
        asset_txbox = self.standard_textbox(frame[0], label_text="Assets (seperated by comma, colon, semicolon, or whitespace)")
        self.standard_button(frame[1], text="Delete", command=delete_assets)
        output_txbox = self.standard_textbox(frame[2], "Output")

    def copy_from_hot_key(self, event, value):
        logging.DEBUG(f"Event Called {event}")
        self.window.clipboard_append(string=value)

    
    def run_ipinfo(self, ip):
            return_text = ""
            return_dict = {}
            try:
                ip = Pinmap.validate_ip(ip)
            except Exception as e:
                logging.ERROR(str(e))
                return None, None
            try:
                response = requests.get(url=f"https://www.ipinfo.io/{ip}/")
                jsponse = response.json()
            except: 
                response = requests.get(url=f"https://www.ipinfo.io/{ip}/", verify=False)
                jsponse = response.json()
            for key in jsponse.keys():
                if key in ["country", "hostname", "city", "org", "region"]:
                    return_text += f"{key}: {jsponse[key]}\n"
                    return_dict[key] = jsponse[key]
            return return_text, return_dict
    
    def ip_dig(self, frame):
        ip_addr = tk.StringVar()
        hostname = tk.StringVar()
        def run_nslookup():
            results_text.delete("1.0", tk.END)
            ip = ip_addr.get()
            host = hostname.get()
            if len(ip) < 4 and len(host) > 4:
                try: 
                    ip = socket.gethostbyname(host)
                    ip_addr.set(ip)
                except Exception as e: ip_addr.set(str(e))
            elif len(host) < 4 and len(ip) > 4:
                try:
                    host = socket.gethostbyaddr(ip)[0]
                    hostname.set(host)
                except Exception as e: hostname.set(str(e))

        def run_ipinfo():
            results_text.delete("1.0", tk.END)
            ip = ip_addr.get()
            if len(ip) < 7:
                run_nslookup()
                time.sleep(1)
            if len(ip) < 7:
                results_text.insert(tk.END, "Add IP")
                return
            return_text, ret_dict = self.run_ipinfo(ip)
            results_text.insert("1.0", return_text)
            results_text.insert("1.0","IP INFO\n")
        def r7():
            if len(ip_addr.get()) > 6:
                ip = ip_addr.get()
            else: ip = None
            if len(hostname.get()) > 6:
                host = hostname.get()
            else: host = None
            result = InsightVM.get_asset_info(ip=ip, hostname=host)
            results_text.insert("1.0", str(result))
            results_text.insert("1.0", "Rapid7")
        def s1():
            if len(ip_addr.get()) > 6:
                ip = ip_addr.get()
            else: ip = None
            if len(hostname.get()) > 6:
                host = hostname.get()
            else: host = None
            result = SentinelOne.search_asset(device=host, ip=ip)
            results_text.insert("1.0", str(result))
            results_text.insert("1.0", "SentinelOne")
            

        self.standard_input_oneliner(frame[0], text="Hostname:", textvariable=hostname)
        self.standard_input_oneliner(frame[0], text="IP:", textvariable=ip_addr, row=1)
        self.standard_button(frame[1], text="nslookup", command=run_nslookup, row=0, column=0)
        self.standard_button(frame[1], text="ipinfo", command=run_ipinfo, row=0, column=1)
        self.standard_button(frame[1], text="R7", command=r7, row=0, column=2)
        self.standard_button(frame[1], text="S1", command=s1, row=0, column=3)
        results_text = self.standard_textbox(frame[2], label_text="Results:", height=15)
        #headers_text.insert("1.0", str(default_headers))

    def hot_keys(self, frame):
        hot_key = tk.StringVar()
        hot_key.set("<F1>")
        value = tk.StringVar()
        def save_hot_key():
            self.window.bind(hot_key.get().strip(), lambda x: self.copy_from_hot_key(hot_key.get(), value.get()))
        def permanently_save_hot_key():
            save_hot_key()
            config = self.get_config_file()
            config["HOTKEYS"][hot_key.get().strip()] =  value.get()
            self.save_config_file(config)

        self.standard_input_oneliner(frame[0], text="Hot Key to Use:", textvariable=hot_key)
        self.standard_input_oneliner(frame[0], text="Value to Copy:", textvariable=value, row=1)
        self.standard_button(frame[0], text="Save for Session", row=2, command=save_hot_key)
        self.standard_button(frame[0], text="Save Permantly (Plain Text)", row=2, column=1, command=permanently_save_hot_key)

    def black_screen(self, frame):
        self.t = ''
        def activate_black_screen():
            self.t = tk.Toplevel(self.window, background="black")
            self.t.attributes("-fullscreen", True)
            self.t.geometry("9999999x9999999")
            self.t.focus_get()
            self.t.config(cursor='arrow black black')
            self.t.bind("u", exit_black_screen)
        def exit_black_screen(x):
            self.t.destroy()

        self.standard_label(frame[0], text="To turn off the black screen, press 'u'")
        self.standard_button(frame[0], text="Activate Black Screen", row=1, command=activate_black_screen)
        self.standard_button(frame[0], text="Quit Black Screen", row=2, command=exit_black_screen)
        
    def api_query(self, frame):
        url = tk.StringVar()
        url.set("https://catfact.ninja/fact") # Free test api
        method = tk.StringVar()
        method.set("GET")
        verify_ssl = tk.BooleanVar()
        verify_ssl.set(True)
        self.vars += [url, method]

        def send_request():
            response_text.delete("1.0", tk.END)
            try:
                response = requests.request(url = url.get(), method=method.get(), headers=ast.literal_eval(headers_text.get("1.0", tk.END)), 
                                            data=json.dumps(data_text.get("1.0", tk.END)))
                try:
                    response_text.insert("1.0", str(response.json()))
                except: 
                    try: 
                        response_text.insert("1.0", str(response.text))
                    except: 
                        response_text.insert("1.0", "Status Code: " + str(response.status_code))
            except Exception as e:
                response_text.insert("1.0", str(e))

        self.standard_input_oneliner(frame[0], text="URL:", textvariable=url)
        self.standard_input_oneliner(frame[0], text="Method:", textvariable=method, row=1)
        
        default_headers = {'Accept': "application/json", 'User-Agent': "ApiQuery1.0", "Content-Type":"application/json"}
        headers_text = self.standard_textbox(frame[1], label_text="Headers")
        headers_text.insert("1.0", str(default_headers))
        data_text = self.standard_textbox(frame[1], label_text="Data", row=2)
        data_text.insert("1.0", "{}")

        self.standard_checkbuttons(frame[1], text_vars=[["Verify SSL", verify_ssl]], row=4)

        self.standard_button(frame[2], text="Send", command=send_request)
    
        response_text = self.standard_textbox(frame[3], label_text="Response")
   
    def phish_reel(self, frame):
        to_email = tk.StringVar()
        subject = tk.StringVar()
        content = tk.StringVar()
        from_email = tk.StringVar()
        from_name = tk.StringVar()
        output = tk.StringVar()
        use_file_bool = False
        from_email_list = [i[1] + " " + i[2] for i in get_email_options()]
        from_email.set(from_email_list[0])
        self.vars += [to_email, subject, content, output, from_email]

        def send_phish():
            nonlocal use_file_bool
            email_options = get_email_options()
            choice = from_email_list.index(from_email.get())
            nickname = email_options[choice][0]
            fname = None
            if len(from_name.get())>2: fname = from_name.get()
            if use_file_bool:
                with open(content.get(), "r") as f:
                    email_content = f.read()
            else:
                email_content = content.get()
            result = send_email(to_email.get(), subject.get(), email_content, nickname, fname)
            output.set(result)

        def use_file():
            nonlocal use_file_bool
            filename = filedialog.askopenfilename(filetypes=(("html files","*.html"),("All files","*.*")))
            content.set(filename)
            use_file_bool = True

        self.standard_input_oneliner(frame[0], "To (email):", to_email)
        self.standard_input_oneliner(frame[0], "Subject:", subject, row=1)
        self.standard_input_oneliner(frame[0], "Content:", content, row=2)
        self.standard_button(frame[0], "Use File", use_file, row=3, column=1)

        self.standard_input_oneliner(frame[0], "From Name:", from_name, row=4)
        self.standard_options_menu(frame[0], labeltext="From Email:", row=5, column=0, variable=from_email, options=from_email_list)

        self.standard_label(frame[2], text="Output:")
        self.standard_label(frame[2], textvariable=output, width=80, column=1)
 
        self.standard_button(frame[2], "Send", send_phish, column=2)

    def pinmap(self, frame):
        query = tk.StringVar()
        self.vars.append(query)

        def run_pinmap():
            results_text.delete("1.0", tk.END)
            with StringIO("") as file:
                y = Pinmap(query.get(), silence_prints=True, file=file)
                file.seek(0)
                output = file.read()
            results_text.insert("1.0", output)

        self.standard_input_oneliner(frame[0], text="PiNmap", textvariable=query, row=0, width=60)
        self.standard_button(frame[0], column=3, text="Run", command=run_pinmap)

        results_text = self.standard_textbox(frame[1], t_background="lightgrey", height=10)

        help_text = self.standard_textbox(frame[2], t_background="lightgrey", height=5)
        help = """Example Command: 192.168.1.46,192.168.1.1 -p21-22 -sV\nCurrently PiNmap has support for:\n-T = Time 0(slowest) to 5(fastest) 
-p = Port numbers\n-pn = Scan ports even if fail ping\n-sS, -sA, -sX = SYN Scan, ACK Scan, XMAS scan\n-sV = Get Version Info (Banner scan)\n-v = Verbose\n-d/-dd = Increase debug level\n-sn = Ping scan only\n-PR, -PA, -PS = ARP Ping, ACK ping, SYN ping"""
        help_text.insert(tk.END, help + "\n")

    def comparer2(self, frame):
        split_by = tk.StringVar()
        split_by.set("\t")
        self.vars.append(split_by)
        case_sensitive = tk.StringVar()
        case_sensitive.set(0)
        self.vars.append(case_sensitive)
        use_diff = tk.IntVar()
        use_diff.set(1)
        self.vars.append(use_diff)
        strip = tk.StringVar()
        strip.set(1)
        self.vars.append(strip)

        def compare():
            text_1_entry.tag_remove("dupe", "1.0", "end")
            text_2_entry.tag_remove("dupe", "1.0", "end")
            text_1_entry.tag_remove("unique", "1.0", "end")
            text_2_entry.tag_remove("unique", "1.0", "end")

            text_1 = text_1_entry.get("1.0", tk.END)
            text_2 = text_2_entry.get("1.0", tk.END)
            logging.info(f"Comparing")

            if not case_sensitive.get() == 1:
                text_1 = text_1.lower()
                text_2 = text_2.lower()
                text_1_entry.delete("1.0", tk.END)
                text_1_entry.insert("1.0", text_1.lower())
                text_2_entry.delete("1.0", tk.END)
                text_2_entry.insert("1.0", text_2.lower())
                
            if not use_diff.get():
                text_1 = text_1.split(split_by.get())
                text_2 = text_2.split(split_by.get())
                
                if strip.get() == 1:
                    text_1 = [x.strip() for x in text_1]
                    text_2 = [x.strip() for x in text_2]

                both = list(set(text_1 + text_2))

                for text in both: 
                    #pattern = r"[\s" + split_by.get() + "]" + re.escape(text) + r"[\s" + split_by.get() + "]"
                    pattern = "(?:^|[\s" + split_by.get() + "])" + re.escape(text) +"(?:\b|[\s" + split_by.get() + "])"
                    
                    logging.info(f"{pattern}")
                    if text in text_1 and text in text_2:
                        #text_1_entry.highlight_pattern(text, "dupe")
                        #text_2_entry.highlight_pattern(text, "dupe")
                        text_1_entry.highlight_pattern(pattern, "dupe", regexp=True)
                        text_2_entry.highlight_pattern(pattern, "dupe", regexp=True)
                    elif text in text_1:
                        text_1_entry.highlight_pattern(text, "unique")
                        #text_1_entry.highlight_pattern(pattern, "unqiue", regexp=True)
                    elif text in text_2:
                        text_2_entry.highlight_pattern(text, "unique")
                        #text_2_entry.highlight_pattern(pattern, "unqiue", regexp=True)
            else:
                sm = difflib.SequenceMatcher(None, text_1, text_2)
                matches = sm.get_matching_blocks()
                for m in matches:
                    if m.size > 10:
                        text_1_entry.highlight_pattern(text_1[m.a:m.a+m.size], "dupe")
                        text_2_entry.highlight_pattern(text_1[m.a:m.a+m.size], "dupe")    

        text_1_entry = self.standard_textbox(frame[0], label_text="Text #1", t_background="lightgrey")
        text_2_entry = self.standard_textbox(frame[0], label_text="Text #2", t_background="lightgrey", column=1)

        text_1_entry.tag_configure("unique", foreground="blue")
        text_1_entry.tag_configure("dupe", foreground="red")
        text_2_entry.tag_configure("unique", foreground="blue")
        text_2_entry.tag_configure("dupe", foreground="red")

        subframe_1 = self.standard_frame(frame[1])
        subframe_2 = self.standard_frame(frame[1], row=0, column=1)

        self.standard_radio_buttons(subframe_1, label_text="Seperator:", 
                               texts_values=[["'\\n'", "\n"],["', '", ","],["'\\t'", "\t"],["' '", " "]], 
                               variable=split_by)
        self.standard_input_oneliner(subframe_1, text="Other:", textvariable=split_by, row=1, width=5)

        self.standard_checkbuttons(subframe_2, [["Case Sensititive", case_sensitive], ["Strip Excess Space", strip], ["Use Difflib Algo", use_diff]])
        #difflib_chbx.bind("<Button-1>", hide_all)
        #difflib_trace = use_diff.trace("w", hide_all)

        self.standard_button(subframe_2, text="Compare", command=compare, row=1, columnspan=3)

    def comparer(self, frame):
        split_by = tk.StringVar()
        split_by.set("\t")
        self.vars.append(split_by)
        case_sensitive = tk.StringVar()
        case_sensitive.set(0)
        self.vars.append(case_sensitive)
        strip = tk.StringVar()
        strip.set(1)
        self.vars.append(strip)

        def compare():
            text_1 = text_1_entry.get("1.0", tk.END)
            text_2 = text_2_entry.get("1.0", tk.END)
            text_1 = text_1.split(split_by.get())
            text_2 = text_2.split(split_by.get())

            if case_sensitive.get(): 
                text_1 = [x.lower() for x in text_1]
                text_2 = [x.lower() for x in text_2]
            
            if strip.get():
                text_1 = [x.strip() for x in text_1]
                text_2 = [x.strip() for x in text_2]
   
            both = list(set(text_1 + text_2))

            dupes = []
            text_1_unique = []
            text_2_unique = []
            for text in both:
                if text in text_1 and text in text_2:
                    dupes.append(text)
                elif text in text_1:
                    text_1_unique.append(text)
                elif text in text_2:
                    text_2_unique.append(text)
            
            text_1_disp.delete("1.0", tk.END)
            text_1_disp.insert("1.0", split_by.get().join(text_1_unique))

            text_2_disp.delete("1.0", tk.END)
            text_2_disp.insert("1.0", split_by.get().join(text_2_unique))

            dupe_entry.delete("1.0", tk.END)
            dupe_entry.insert("1.0", split_by.get().join(dupes))

            logging.info(f"Compared")
        
        text_1_entry = self.standard_textbox(frame[0], label_text="Text #1", t_background="lightgrey")
        text_2_entry = self.standard_textbox(frame[0], label_text="Text #2", t_background="lightgrey", column=1)

        self.standard_radio_buttons(frame[1], label_text="Seperator:", row=2,
                               texts_values=[["'\\n'", "\n"],["', '", ","],["'\\t'", "\t"],["' '", " "]], 
                               variable=split_by, seperate_label_line=1)

        self.standard_checkbuttons(frame[2], [["Case Sensititive", case_sensitive], ["Strip Excess Space", strip]])

        self.standard_button(frame[2], text="Compare", command=compare, row=1, columnspan=4)

        text_1_disp = self.standard_textbox(frame[3], label_text="Text #1 Unique", t_background="lightgrey", height=5, row=0)
        text_2_disp = self.standard_textbox(frame[3], label_text="Text #2 Unique", t_background="lightgrey", height=5, column=1, row=0)

        dupe_entry = self.standard_textbox(frame[3], label_text="Duplicates", t_background="lightgrey", height=5, width=160, row=2, columnspan=2)

    def replacer(self, frame): 
        in_this_text = tk.StringVar()
        find_this = tk.StringVar()
        replace_w_this = tk.StringVar()
        regex = tk.IntVar()
        regex.set(0)
        self.vars = self.vars + [regex, replace_w_this, find_this, in_this_text]

        def run():
            in_this_text.set(entry.get("1.0", tk.END))
            text = in_this_text.get()
            find = find_this.get()
            replace = replace_w_this.get()

            if regex.get() == 1:
                sub = re.sub(find, replace, text)
                in_this_text.set(sub)
            else:
                text = text.replace(find, replace)
                in_this_text.set(text)
            entry.delete("1.0", tk.END)
            entry.insert(tk.END, in_this_text.get())
            logging.info(f"Replaced")

        entry = self.standard_textbox(frame[0], width=100, height=5)
        entry.insert(tk.END, in_this_text.get())
        self.standard_label(frame[0], text=" ", row=2, column=0)

        self.standard_radio_buttons(frame[1], label_text="Type:", row=0,
                        texts_values=[["Regex", 1],["Standard", 0]], 
                        variable=regex, no_label=1)

        self.standard_input_oneliner(frame[1], text="Find:", textvariable=find_this, width=25, row=1)
        self.standard_input_oneliner(frame[1], text="Replace With:", textvariable=replace_w_this, width=25, row=2, column=0)

        self.standard_button(frame[1], width=45, text="Run", height=5, command=run, column=3, rowspan=3)
        # run_button = tk.Button(frame[1], width=45, height=5, text="Run", command=run)
        # run_button.grid(column=3, row=0, rowspan=3)

    def combiner(self, frame):
        seperator = tk.StringVar()
        seperator.set(", ")
        result = tk.StringVar()
        clipboard = [] 
        self.vars = self.vars + [seperator, result]

        def get_clips():
            accum = 0
            try: 
                first = self.window.clipboard_get()
            except _tkinter.TclError:
                first = ""
            
            while accum < 4:
                self.window.after(1000)
                try: 
                    x = self.window.clipboard_get()
                except _tkinter.TclError:
                    x = ""
                logging.info(f"Clipboard has {x}")
                if x.strip() not in clipboard and x.strip() != "" and x is not None and x != first: 
                    clipboard.append(x.strip())
                    accum = 0
                else: 
                    accum +=1
                #result.set("Seconds Left: " + str(int((9-accum)/2))) Does not work.
            result.set("Done")
            logging.info(f"Got clips")

        def copy_value():
            sep = str(seperator.get())
            self.window.clipboard_append(string=sep.join(clipboard)) 
            result.set(sep.join(clipboard))
            logging.info(f"Copied")

        def reset():
            result.set("")
            self.destroy_frames()
            logging.info(f"Reset")
            self.standard_window(self.combiner, "ClipBoard Combiner 1.0")

        def show_value():
            sep = str(seperator.get())
            outcome= sep.join(clipboard)
            messagebox.showinfo(title="Result", message=outcome)
            logging.info(f"Showing")

        self.standard_button(frame[0], text="Play", command=get_clips, width=10)
        self.standard_button(frame[0], text="Reset", command=reset, width=10, column=1)
        self.standard_button(frame[0], text="Copy", command=copy_value, width=10, column=2)
        self.standard_button(frame[0], text="Show", command=show_value, width=10, column=3)
      
        self.standard_radio_buttons(frame[0], label_text="Seperator:", row=1,
                               texts_values=[["'\\n'", "\n"],["', '", ","],["'\\t'", "\t"],["' '", " "]], 
                               variable=seperator, seperate_label_line=1)

        self.standard_label(frame[1], text="Result:")
        self.standard_label(frame[1], textvariable=result, background="lightblue", row=1)
        self.standard_label(frame[1], row=2, text="Press 'Play', copy each item you need, wait until we say 'Done'\n Press 'Show' to check progress. Do not press 'Copy' until done.")
        

    def link_checker(self, frame): 
        link_unwrapped = tk.StringVar()
        link_unwrapped.set("")
        scan_results = tk.StringVar()

        self.vars = self.vars + [link_unwrapped, scan_results]

        def decode():
            link = entry_1.get("1.0", tk.END)
            link_unwrapped.set(URL_decode(link))

            entry_2.delete("1.0", tk.END)
            entry_2.insert(tk.END, link_unwrapped.get())
            logging.info(f"Decoding")
        
        def vt_scan():
            scan_results.set("Scanning...")
            if link_unwrapped.get() == "": decode()
            link = link_unwrapped.get()
            config = self.get_config_file()
            key = config["VT"]["virus_total_key"]
            
            def get_vt_report(key = key):
                url = 'https://www.virustotal.com/vtapi/v2/url/report'
                params = {'apikey': key, 'resource':link}
                try:
                    response = requests.get(url, params=params, timeout=10000)
                except: 
                    response = requests.get(url, params=params, verify=False, timeout=10000)
                try: r = response.json()
                except: return response.text()
                results = {}
                for scan in r["scans"]:
                    rating = r["scans"][scan]["result"]
                    if rating not in results.keys():
                        results[rating] = 1
                    else:
                        results[rating] = results[rating] + 1
                return results
            try:
                scan_results.set(str(get_vt_report(key=key)))
            except KeyError:
                url = "https://www.virustotal.com/api/v3/urls"
                payload = { "url": link }
                headers = {
                    "accept": "application/json",
                    "content-type": "application/x-www-form-urlencoded",
                    "X-Apikey": key
                }
                try:
                    response = requests.post(url, data=payload, headers=headers, timeout=10000)
                except:
                    response = requests.post(url, data=payload, headers=headers, verify=False, timeout=10000)
                scan_stat = response.json()["data"]["links"]["self"]
                scan_results.set(f"View Results at: {scan_stat}")
                time.sleep(20)
                try:
                    scan_results.set(str(get_vt_report(key=key)))
                except Exception as e:
                    scan_results.set(str(e))
                logging.info(f"Scanning")

        def url_scan():
            scan_results.set("Scanning...")
            if link_unwrapped.get() == "": decode()
            link = link_unwrapped.get()
            config = self.get_config_file()
            key = config["url_scan"]["url_scan_key"]
            def submit_url(link):
                headers = {'API-Key': key, 'Content-Type':'application/json'}
                data = {"url": link, "visibility": "public"}
                try:
                    response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
                except: 
                    response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data), verify=False)
                if response.status_code != 200:
                    print(response.json()["description"])
                    scan_results.set("Error:" + response.json()["description"])
                    return False
                else:
                    uuid = response.json()["uuid"]
                    scan_results.set(f"Submitted, uuid is {uuid}...")
                    return uuid

            def get_url(uuid):
                try:
                    try:
                        response = requests.request("GET", url = f"https://urlscan.io/api/v1/result/{uuid}/")
                    except: 
                        response = requests.request("GET", url = f"https://urlscan.io/api/v1/result/{uuid}/", verify=False)
                    if response.status_code == 404:
                        logging.info(str(response.status_code))
                        #print(response.text)
                        return False
                    else:
                        JSON = response.json()
                        mal = JSON["verdicts"]["overall"]["malicious"]
                        end = JSON["page"]["url"]
                        countries = JSON["lists"]["countries"]
                        link_unwrapped.set(end)
                        scan_results.set(f"Malicous: {mal}, Countries {countries}")
                        #get_image(uuid)
                        return True
                except Exception as e: logging.info(e)
            def get_image(uuid):
                """ Not exactly what you would call "working" yet """
                try:
                    from PIL import ImageTk
                    from urllib.request import urlopen
                    url = f"https://urlscan.io/screenshots/{uuid}.png"
                    logging.info(f"Requesting {url}") 
                    newwin = tk.Toplevel(self.window)
                    image = ImageTk.PhotoImage(file=urlopen(url))
                    label = tk.Label(newwin, image = image)
                    label.pack()
                except Exception as e:
                    logging.info(e)

            uuid = submit_url(link)
            if uuid is not False:
                self.window.after(5000, get_url, (uuid))
                self.window.after(10000, get_url, (uuid))
                self.window.after(15000, get_url, (uuid))
                # self.window.after(15000, get_image, (uuid))
            logging.info("URL scan done")
                    
        entry_1 = self.standard_textbox(frame[0], label_text="URL:", width=50, height=2)
        entry_2 = self.standard_textbox(frame[0], label_text="Unwrapped:", width=50, height=2, row=2)

        self.standard_input_oneliner(frame[1], text="Results:", textvariable=scan_results, width=75, columnspan=2, across=False)

        self.standard_button(frame[2], text="Decode", command=decode, row=2)
        self.standard_button(frame[2], text="VirusTotal", command=vt_scan, row=2, column=1)
        self.standard_button(frame[2], text="URLscan.io", command=url_scan, row=2, column=2)

#Run code.
SOCer()
# def run_SOCer():
#     SOCer()

# import threading
# threads = []

# def add_SOCer_window():
#     th2 = threading.Thread(target=run_SOCer)
#     threads.append(th2)
#     th2.start()

# th1 = threading.Thread(target=run_SOCer)
# threads.append(th1)
# th1.start()

# for thread in threads:
#     thread.join()




