"""A GUI assistant for a security operations center. 
Contains several useful programs and references."""

import re
import os
import difflib
import tkinter as tk
from tkinter import messagebox
import _tkinter
import time
import logging
import configparser
from io import StringIO
import requests
import json
import ast
import subprocess

from URLdecoder import decode as URL_decode
from phish_reel import send_email, get_email_options
from pinmap import Pinmap
from r7_tools import InsightVM
#from port_scan import PortScan


FORMAT = "%(asctime)s: %(levelname)s: %(message)s (File %(filename)s: Function %(funcName)s: Line %(lineno)d)"

logging.basicConfig(level=logging.INFO, format=FORMAT, datefmt='%H:%M:%S')



#This is for Visual Studio which does not run from files directory.
#This program uses relative file paths.
os.chdir(os.path.dirname(__file__))

#TO ADD:
### Remove assets R7 (list)
### R7 query/S1 Query 
### References/Notes? 
### Ip/hostname dig (nslookup/free API)
### URL dig.

class CustomText(tk.Text):
    '''A text widget with a new method, highlight_pattern()

    example:

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
    def __init__(self):
        self.frames = []
        self.vars = []
        self.window = tk.Tk()
        self.window.title("SOCer")
        #self.window.tk.call('wm', 'iconphoto', self.window._w, tk.PhotoImage(file='SOCer.png'))
        
        def about_app():
            messagebox.showinfo(title="About", message="Author: ExplainItAgain")
        
        # main menu creation
        main_menu = tk.Menu(self.window)
        self.window.config(menu=main_menu)

        # 1nd main menu item: a simple callback
        #sub_menu_help = tk.Menu(main_menu)
        main_menu.add_command(label="About", command=about_app)
        
        # 2st main menu item: an empty (as far) submenu
        program_menu = tk.Menu(main_menu)
        main_menu.add_cascade(label="Programs", menu=program_menu, underline=0)

        #program_menu.add_command(label="Combiner", command=lambda: self.standard_window(self.combiner, "ClipBoard Combiner 1.0"), underline=0)
        # program_menu.add_command(label="Find&Replace", command=lambda: self.standard_window(self.replacer, "Replacer 1.0"), underline=0)
        # program_menu.add_command(label="LinkCheck", command=lambda: self.standard_window(self.link_checker, "LinkCheck 1.0"), underline=0)
        # program_menu.add_command(label="Compare", command=lambda: self.standard_window(self.comparer, "Comparer 1.0"), underline=0)
        # program_menu.add_command(label="Compare2.0", command=lambda: self.standard_window(self.comparer2, "Comparer 2.0"), underline=0)
        # program_menu.add_command(label="PiNmap", command=lambda: self.standard_window(self.pinmap, "PiNmap 1.0"), underline=0)
        # program_menu.add_command(label="PhishReel", command=lambda: self.standard_window(self.phish_reel, "PhishReel 1.0"), underline=0)
        # program_menu.add_command(label="APIquery", command=lambda: self.standard_window(self.api_query, "API Query 1.0"), underline=0)
        # program_menu.add_command(label="BlackScreen", command=lambda: self.standard_window(self.black_screen, "Black Screen 1.0"), underline=0)
        # program_menu.add_command(label="HotKeys", command=lambda: self.standard_window(self.hot_keys, "Hot Keys 1.0"), underline=0)
        # program_menu.add_command(label="IP Dig", command=lambda: self.standard_window(self.ip_dig, "IP Dig 2.0"), underline=0)

        tabs = [
            {"name":"ClipBoard Combiner 1.0", "command": self.combiner},
            {"name":"Find&Replace 1.0", "command": self.replacer},
            {"name":"Comparer 1.0", "command": self.comparer},
            {"name":"Comparer 2.0", "command": self.comparer2},
            {"name":"PiNmap 1.0", "command": self.pinmap},
            {"name":"PhishReel 1.0", "command": self.phish_reel},
            {"name":"API Query 1.0", "command": self.api_query},
            {"name":"Black Screen 1.0", "command": self.black_screen},
            {"name":"Hot Keys 1.0", "command": self.hot_keys},
            {"name":"IP Dig 2.0", "command": self.ip_dig},
            {"name":"LinkCheck 1.0", "command": self.link_checker},
            {"name":"R7 Delete Assets 1.0", "command": self.ivm_delete_assets}
            # {"name":"", "command": self.},
            # {"name":"", "command": self.},
            # {"name":"", "command": self.}
            ]
        for tab in tabs: 
            program_menu.add_command(label=tab["name"], command=lambda: self.standard_window(tab["command"], tab["name"]), underline=0)
        # reference_files = os.listdir("./reference")
        
        # reference_menu = tk.Menu(main_menu)
        # main_menu.add_cascade(label="Reference", menu=reference_menu, underline=0)

        # for file in reference_files:
        #     reference_menu.add_command(label=file, command=lambda: ref_tab(file), underline=0)
        
        label_frame_1 = tk.LabelFrame(self.window, text="Welcome",
            width=100, height=100, bg='white')
        self.frames.append(label_frame_1)
        
        welcome_label = tk.Label(label_frame_1, background="white", 
                                 text="Please browse the programs and reference lists available. \nIf you have not already, I'd recommend adding python to path \nand adding the 'SOCer.bat' script to a directory in path")
        welcome_label.grid(column=0, row=0, padx=50, pady=50)
        label_frame_1.pack()

        self.load_hot_keys()
        
        self.window.mainloop()
        logging.info("SOCer Initiated")
        
    def destroy_frames(self):
        for frame in self.frames:
            frame.destroy()
        for var in self.vars:
            del var
    
    def standard_input_oneliner(self, frame, text, textvariable, row=0, width=95,l_background="white", e_background="lightgrey"):
        temp_label = tk.Label(frame, text=text, background=l_background)
        temp_label.grid(row=row, column=0)#, columnspan=2)
        temp_entry = tk.Entry(frame, background=e_background, textvariable=textvariable, width=width)#, height=5)
        temp_entry.grid(row=row, column = 1, columnspan=1)

    def standard_button(self, frame, text, command, row=0, column=0, columnspan=1, rowspan=1, width=20, height=1):
        temp_button = tk.Button(frame, text=text, command=command, background="slategray1", activebackground="blue", width=width, height=height)
        temp_button.grid(row=row, column=column, columnspan=columnspan, rowspan=rowspan)

    def standard_radio_buttons(self, frame, label_text, texts_values: list[list], variable, row=0, column=0, seperate_label_line=0, no_label=0):
            if not no_label:
                temp_label = tk.Label(frame, text=label_text, background= "white")
                temp_label.grid(row=row, column=column)
            if seperate_label_line:
                row += 1
            if not seperate_label_line and not no_label:
                column += 1
            for switch_list in texts_values:
                radio_switch = tk.Radiobutton(frame, text = switch_list[0], variable = variable, 
                                                value = switch_list[1])#, background= "white")
                radio_switch.grid(row=row, column=column)
                column += 1      
    def standard_textbox(self, frame, label_text, row=0, column=0, height=5, width=80,l_background="white", t_background="lightgrey"):
        temp_label = tk.Label(frame, text=label_text, background=l_background)
        temp_label.grid(row=row, column=column)
        temp_text = tk.Text(frame, background=t_background, height=height, width=width)
        temp_text.grid(row=row+1, column=column)  
        return temp_text
        
    def standard_window(self, function, label=""):
        self.destroy_frames()
        label_frame_1 = tk.LabelFrame(self.window, text=label, bg='white')
        label_frame_2 = tk.LabelFrame(self.window, bg='white')
        label_frame_3 = tk.LabelFrame(self.window, bg='white')
        label_frame_4 = tk.LabelFrame(self.window, bg='white')
        self.frames = [label_frame_1, label_frame_2, label_frame_3, label_frame_4]

        function(frame = self.frames)

        for frame in self.frames: frame.pack()

    def ivm_delete_assets(self, frame):
        output_txbox.delete("1.0", tk.END)
        def delete_assets():
            assets = re.split("[\s;:,]", asset_txbox.get("1.0", tk.END))
            for asset in assets:
                ids = InsightVM.remove_asset(asset)
                output_txbox.insert(tk.END, f"{asset} : Results {str(ids)}")
        asset_txbox = self.standard_textbox(frame[0], label_text="Assets (seperated by comma, colon, semicolon, or whitespace)")
        self.standard_button(frame[1], text="Delete", command=delete_assets)
        output_txbox = self.standard_textbox(frame[1], "Output")

    def copy_from_hot_key(self, event, value):
        logging.DEBUG(f"Event Called {event}")
        self.window.clipboard_append(string=value)

    def get_config_file(self):
        config = configparser.ConfigParser()
        try: config.read("localonly.SOCer.config")
        except: config.read("SOCer.config")
        return config
    
    def save_config_file(self, config):
        try:
            with open("localonly.SOCer.config", "w") as f: 
                config.write(f)
        except: 
            with open("SOCer.config", "w") as f: 
                config.write(f)

    def load_hot_keys(self):
        config = self.get_config_file()
        for key in config["HOTKEYS"].keys():
            self.window.bind(key.upper(), lambda x: self.copy_from_hot_key(key, config["HOTKEYS"][key]))

    def ip_dig(self, frame):
        ip_addr = tk.StringVar()
        hostname = tk.StringVar()
        def run_nslookup():
            results_text.delete("1.0", tk.END)
            def call_with_output(query):
                success = False
                try:
                    output = subprocess.check_output(query, stderr=subprocess.STDOUT).decode()
                    success = True 
                except subprocess.CalledProcessError as e:
                    output = e.output.decode()
                except Exception as e:
                    # check_call can raise other exceptions, such as FileNotFoundError
                    output = str(e)
                return(success, output)
            nslookup = call_with_output(str(f"nslookup {ip}"))
            if "***" not in nslookup[1]:
                nslookup = "\n".join(nslookup[1].split("\n")[3:]).strip()
            else:
                nslookup = nslookup[1].split("\n")[0]
            results_text.insert(tk.END, f"nslookup:\n{nslookup}")

        def run_ipinfo():
            results_text.delete("1.0", tk.END)
            ip = ip_addr.get()


        self.standard_input_oneliner(frame[0], text="Hostname:", textvariable=hostname)
        self.standard_input_oneliner(frame[0], text="IP:", textvariable=ip_addr)
        self.standard_button(frame[1], text="nslookup", command=run_nslookup, row=0, column=0)
        self.standard_button(frame[1], text="ipinfo", command=run_ipinfo, row=0, column=1)
        results_text = self.standard_textbox(frame[2], label_text="Results:")
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

        label = tk.Label(frame[0], text="To turn off the black screen, press 'u'")
        label.grid(row=0, column=0)
        self.standard_button(frame[0], text="Activate Black Screen", row=1, command=activate_black_screen)
        self.standard_button(frame[0], text="Quit Black Screen", row=2, command=exit_black_screen)
        
    def api_query(self, frame):
        url = tk.StringVar()
        url.set("https://catfact.ninja/fact") # Free test api
        method = tk.StringVar()
        method.set("GET")
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

        self.standard_button(frame[2], text="Send", command=send_request)

        response_text = self.standard_textbox(frame[3], label_text="Response")
   
    def phish_reel(self, frame):
        to_email = tk.StringVar()
        subject = tk.StringVar()
        content = tk.StringVar()
        from_email = tk.StringVar()
        output = tk.StringVar()
        from_email_list = [i[1] + " " + i[2] for i in get_email_options()]
        from_email.set(from_email_list[0])
        self.vars += [to_email, subject, content, output, from_email]

        def send_phish():
            email_options = get_email_options()
            choice = from_email_list.index(from_email.get())
            nickname = email_options[choice][0]
            result = send_email(to_email.get(), subject.get(), content.get(), nickname)
            output.set(result)

        self.standard_input_oneliner(frame[0], "To (email):", to_email)
        self.standard_input_oneliner(frame[0], "Subject:", subject, row=1)
        self.standard_input_oneliner(frame[0], "Content:", content, row=2)
        from_label = tk.Label(frame[0], text="From Email:", background="white")
        from_label.grid(row=3, column=0)#, columnspan=2)
        from_email_entry = tk.OptionMenu(frame[0], from_email, *from_email_list)
        from_email_entry.grid(row=3, column=1)

        output_label = tk.Label(frame[2], text="Output:", background="white")
        output_label.grid(row=0, column=0)
        output_box = tk.Label(frame[2], textvariable=output, background="white", width=80)
        output_box.grid(row=0, column=1)
 
        self.standard_button(frame[2], "Send", send_phish, column=2)

    def pinmap(self, frame):
        query = tk.StringVar()
        self.vars.append(query)

        def run_pinmap():
            with StringIO("") as file:
                Pinmap(query.get(), silence_prints=True, file=file)
                file.seek(0)
                output = file.read()
            results_text.insert("1.0", output)
                

        self.standard_input_oneliner(frame[0], text="PiNmap", textvariable=query, row=0)
        self.standard_button(frame[0], column=3, text="Run", command=run_pinmap)

        results_text = tk.Text(frame[1], background="lightgrey", height=10)
        results_text.grid(row=0, column=0)

        help_text = tk.Text(frame[2], background="lightgrey", height=5)
        help_text.grid(row=0, column=0)
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
        
        text_1_label = tk.Label(frame[0], text="Text #1", background="white")
        text_1_label.grid(row=0, column=0)#, columnspan=2)
        text_2_label = tk.Label(frame[0], text="Text #2", background="white")
        text_2_label.grid(row=0, column=1)#, columnspan=2)

        text_1_entry = CustomText(frame[0], background="lightgrey")#, height=5)
        text_1_entry.grid(row=1, column = 0)#, columnspan=2)
        text_1_entry.tag_configure("unique", foreground="blue")
        text_1_entry.tag_configure("dupe", foreground="red")
        text_2_entry = CustomText(frame[0], background="lightgrey")#, height=5)
        text_2_entry.grid(row=1, column = 1)#, columnspan=2)
        text_2_entry.tag_configure("unique", foreground="blue")
        text_2_entry.tag_configure("dupe", foreground="red")

        self.standard_radio_buttons(frame[1], label_text="Seperator:", 
                               texts_values=[["'\\n'", "\n"],["', '", ","],["'\\t'", "\t"],["' '", " "]], 
                               variable=split_by)
        self.standard_input_oneliner(frame[1], text="Other:", textvariable=split_by, row=1, width=5)
        # label_split_by_entry = tk.Label(frame[1], text = "Other:")
        # entry_split_by = tk.Entry(frame[1], textvariable=split_by)

        case_chbx = tk.Checkbutton(frame[2], text="Case Sensitive", variable=case_sensitive)
        strip_chbx = tk.Checkbutton(frame[2], text="Strip Excess Space", variable=strip)
        difflib_chbx = tk.Checkbutton(frame[2], text="Use Difflib Algo", variable=use_diff)
        case_chbx.grid(row=0, column=0, columnspan=1)
        difflib_chbx.grid(row=0, column=1)
        #difflib_chbx.bind("<Button-1>", hide_all)
        #difflib_trace = use_diff.trace("w", hide_all)

        self.standard_button(frame[2], text="Compare", command=compare, row=1, columnspan=2)

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
        
        text_1_label = tk.Label(frame[0], text="Text #1", background="white")
        text_1_label.grid(row=0, column=0, columnspan=2)
        text_2_label = tk.Label(frame[0], text="Text #2", background="white")
        text_2_label.grid(row=0, column=2, columnspan=2)

        text_1_entry = tk.Text(frame[0], background="lightgrey", height=5)
        text_1_entry.grid(row=1, column = 0, columnspan=2)
        text_2_entry = tk.Text(frame[0], background="lightgrey", height=5)
        text_2_entry.grid(row=1, column = 2, columnspan=2)

        self.standard_radio_buttons(frame[0], label_text="Seperator:", row=2,
                               texts_values=[["'\\n'", "\n"],["', '", ","],["'\\t'", "\t"],["' '", " "]], 
                               variable=split_by, seperate_label_line=1)
        #self.standard_input_oneliner(frame[0], text="Other:", textvariable=split_by, row=2, width=5)

        case_chbx = tk.Checkbutton(frame[1], text="Case Sensitive", variable=case_sensitive)
        strip_chbx = tk.Checkbutton(frame[1], text="Strip Excess Space", variable=strip)
        case_chbx.grid(row=0, column=0, columnspan=2)
        strip_chbx.grid(row=0, column=2, columnspan=2)

        self.standard_button(frame[1], text="Compare", command=compare, row=1, columnspan=4)
        

        text_1_label_2 = tk.Label(frame[2], text="Text #1 Unique", background="white")
        text_1_label_2.grid(row=0, column=0)
        text_2_label_2 = tk.Label(frame[2], text="Text #2 Unique", background="white")
        text_2_label_2.grid(row=0, column=1)

        text_1_disp = tk.Text(frame[2], background="lightgrey", height=5)
        text_1_disp.grid(row=1, column=0)
        text_2_disp = tk.Text(frame[2], background="lightgrey", height=5)
        text_2_disp.grid(row=1, column=1)

        dupe_label = tk.Label(frame[2], text="Duplicates", background="white")
        dupe_label.grid(row=2, column=0, columnspan=2)

        dupe_entry = tk.Text(frame[2], background="lightgrey", height=5, width=160)
        dupe_entry.grid(row=3, column=0, columnspan=2)

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

        entry = tk.Text(frame[0], width=100, height=5)
        entry.insert(tk.END, in_this_text.get())
        entry.grid(row=0, column=0, rowspan=1)
        blank_label = tk.Label(frame[0], text=" ", background="white") 
        blank_label.grid(row=2, column=0)

        # radio_switch_1 = tk.Radiobutton(frame[1], text = "Regex", variable = regex,
        #                                 value = 1, background= "white")
        # radio_switch_2 = tk.Radiobutton(frame[1], text = "Standard", variable = regex,
        #                                 value = 0, background= "white")
        # radio_switch_1.grid(row=0, column=0)
        # radio_switch_2.grid(row=0, column=1)
        self.standard_radio_buttons(frame[1], label_text="Type:", row=0,
                        texts_values=[["Regex", 1],["Standard", 0]], 
                        variable=regex, no_label=1)

        find_label = tk.Label(frame[1], text="Find:", background="white") 
        replace_label = tk.Label(frame[1], text="Replace With:", background="white") 
        find_label.grid(row=1, column=0)
        replace_label.grid(row=1, column=1)

        entry_find = tk.Entry(frame[1], textvariable=find_this, width=25)
        entry_find.grid(row=2, column=0)
        entry_replace = tk.Entry(frame[1], textvariable=replace_w_this, width=25)
        entry_replace.grid(row=2, column=1)

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


        result_label = tk.Label(frame[1], textvariable=result, background="lightblue") 
        result_label_2 = tk.Label(frame[1], text="Result:", background="white") 
        instructions_label = tk.Label(frame[1], background="white",
                                      text="Press 'Play', copy each item you need, wait until we say 'Done'\n Press 'Show' to check progress. Do not press 'Copy' until done.") 
        result_label_2.grid(row=0, column=0)
        result_label.grid(row=1, column=0)
        instructions_label.grid(row=2, column=0)

    def link_checker(self, frame): 
        link_unwrapped = tk.StringVar()
        link_unwrapped.set("")
        vt_results = tk.StringVar()

        self.vars = self.vars + [link_unwrapped, vt_results]

        def decode():
            link = entry_1.get("1.0", tk.END)
            link_unwrapped.set(URL_decode(link))

            entry_2.delete("1.0", tk.END)
            entry_2.insert(tk.END, link_unwrapped.get())
            logging.info(f"Decoding")
        
        def vt_scan():
            link = link_unwrapped.get()
            if link == "": 
                link = entry_1.get("1.0", tk.END)
            else:
                config = self.get_config_file()
                key = config["VT"]["virus_total_key"]
                
                def get_vt_report(key = key):
                    url = 'https://www.virustotal.com/vtapi/v2/url/report'
                    params = {'apikey': key, 'resource':link}
                    response = requests.get(url, params=params, verify=False, timeout=10000)
                    r = response.json()
                    results = {}
                    for scan in r["scans"]:
                        rating = r["scans"][scan]["result"]
                        if rating not in results.keys():
                            results[rating] = 1
                        else:
                            results[rating] = results[rating] + 1
                    return results
                try:
                    vt_results.set(str(get_vt_report(key=key)))
                except KeyError:
                    url = "https://www.virustotal.com/api/v3/urls"
                    payload = { "url": link }
                    headers = {
                        "accept": "application/json",
                        "content-type": "application/x-www-form-urlencoded",
                        "X-Apikey": key
                    }
                    response = requests.post(url, data=payload, headers=headers, verify=False, timeout=10000)
                    scan_stat = response.json()["data"]["links"]["self"]
                    vt_results.set(f"View Results at: {scan_stat}")
                time.sleep(20)
                try:
                    vt_results.set(str(get_vt_report(key=key)))
                except Exception as e:
                    vt_results.set(str(e))
            logging.info(f"Scanning")

        label_1 = tk.Label(frame[0], text="URL:", background="white") 
        label_1.grid(row=0, column=0)
        entry_1 = tk.Text(frame[0], width=50, height=2, background="lightgrey")
        entry_1.grid(row=1, column=0, rowspan=1)

        label_2 = tk.Label(frame[0], text="Unwrapped:", background="white") 
        label_2.grid(row=2, column=0)
        entry_2 = tk.Text(frame[0], width=50, height=2, background="lightgrey")
        entry_2.grid(row=3, column=0, rowspan=1)

        vt_label = tk.Label(frame[1], text="VT Results:", background="white") 
        vt_label.grid(row=0, column=0, columnspan=2)

        entry_vt = tk.Entry(frame[1], textvariable=vt_results, width=75)
        entry_vt.grid(row=1, column=0, columnspan=2)

        self.standard_button(frame[2], text="Decode", command=decode, row=2)
        self.standard_button(frame[2], text="VirusTotal", command=vt_scan, row=2, column=1)

        # decode_button = tk.Button(frame[2], width=20, text="Decode", command=decode)
        # decode_button.grid(column=0, row=2, rowspan=1)
        # vt_button = tk.Button(frame[2], width=20, text="VirusTotal", command=vt_scan)
        # vt_button.grid(column=1, row=2, rowspan=1)

#Run code.
x = SOCer()


