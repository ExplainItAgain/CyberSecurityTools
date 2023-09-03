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

import requests

from URLdecoder import decode, URLDefenseDecoder as URLdecode
from phish_reel import send_email, get_email_options
#from port_scan import PortScan


FORMAT = "%(asctime)s: %(levelname)s: %(message)s (File %(filename)s: Function %(funcName)s: Line %(lineno)d)"

logging.basicConfig(level=logging.INFO, format=FORMAT, datefmt='%H:%M:%S')



#This is for Visual Studio which does not run from files directory.
#This program uses relative file paths.
os.chdir(os.path.dirname(__file__))

#TO ADD:
### Basic API Client
### PhishAFriend Basic 
### Nmap
### Remove assets R7
### R7 query/S1 Query 
### Hot key copy/paste?

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

        def combiner_tab():
            self.destroy_frames()
            self.standard_window(self.combiner, "ClipBoard Combiner 1.0")

        def replacer_tab():
            self.destroy_frames()
            self.standard_window(self.replacer, "Replacer 1.0")

        def linkcheck_tab():
            self.destroy_frames()
            self.standard_window(self.link_checker, "LinkCheck 1.0")

        def comparer_tab():
            self.destroy_frames()
            self.standard_window(self.comparer, "Comparer 1.0")

        def comparer2_tab():
            self.destroy_frames()
            self.standard_window(self.comparer2, "Comparer 2.0")
        
        def pinmap_tab():
            self.destroy_frames()
            self.standard_window(self.pinmap, "PiNmap 1.0")

        def phish_reel_tab():
            self.destroy_frames()
            self.standard_window(self.phish_reel, "PhishReel 1.0")

        def ref_tab(file):
            with open("reference/"+file, "r") as ref:
                messagebox.showinfo(title=file, message = ref.read())

        # main menu creation
        main_menu = tk.Menu(self.window)
        self.window.config(menu=main_menu)

        # 1nd main menu item: a simple callback
        #sub_menu_help = tk.Menu(main_menu)
        main_menu.add_command(label="About", command=about_app)
        
        # 2st main menu item: an empty (as far) submenu
        program_menu = tk.Menu(main_menu)
        main_menu.add_cascade(label="Programs", menu=program_menu, underline=0)

        program_menu.add_command(label="Combiner", command=combiner_tab, underline=0)
        program_menu.add_command(label="Find&Replace", command=replacer_tab, underline=0)
        program_menu.add_command(label="LinkCheck", command=linkcheck_tab, underline=0)
        program_menu.add_command(label="Compare", command=comparer_tab, underline=0)
        program_menu.add_command(label="Compare2.0", command=comparer2_tab, underline=0)
        program_menu.add_command(label="PiNmap", command=pinmap_tab, underline=0)
        program_menu.add_command(label="PhishReel", command=phish_reel_tab, underline=0)

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
        
        self.window.mainloop()

        logging.info("SOCer Initiated")
        
    def destroy_frames(self):
        for frame in self.frames:
            frame.destroy()
        for var in self.vars:
            del var
    
    def get_item_oneliner(self, frame, text, textvariable, row=0, width=95,l_background="white", e_background="lightgrey"):
        temp_label = tk.Label(frame, text=text, background=l_background)
        temp_label.grid(row=row, column=0)#, columnspan=2)
        temp_entry = tk.Entry(frame, background=e_background, textvariable=textvariable, width=width)#, height=5)
        temp_entry.grid(row=row, column = 1, columnspan=1)

    def standard_button(self, frame, text, command, row=0, column=0, columnspan=1):
        temp_button = tk.Button(frame, text=text, command=command, background="lightblue", activebackground="blue")
        temp_button.grid(row=row, column=column, columnspan=columnspan)

    def standard_window(self, function, label=""):
        label_frame_1 = tk.LabelFrame(self.window, text=label,
                                    width=100, height=100, bg='white')
        label_frame_2 = tk.LabelFrame(self.window, width=100, bg='white')
        label_frame_3 = tk.LabelFrame(self.window, width=100, height=100, bg='white')
        self.frames = [label_frame_1, label_frame_2, label_frame_3]

        function(frame = [label_frame_1, label_frame_2, label_frame_3])

        label_frame_1.pack()
        label_frame_2.pack()
        label_frame_3.pack()
    
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

        self.get_item_oneliner(frame[0], "To (email):", to_email)
        self.get_item_oneliner(frame[0], "Subject:", subject, row=1)
        self.get_item_oneliner(frame[0], "Content:", content, row=2)
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

        self.get_item_oneliner(frame[0], text="PiNmap", textvariable=query, row=0)
        self.standard_button(frame[0], column=3, text="Run", command=lambda: x)

        results_text = tk.Text(frame[1], background="lightgrey", height=10)
        results_text.grid(row=0, column=0)

        help_text = tk.Text(frame[2], background="lightgrey", height=5)
        help_text.grid(row=0, column=0)
        help = """help info"""
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

        def hide_all(*args): 
            
            frame[1].pack_forget()

            sep_label.grid(row=1, column=0)
            radio_switch_1.grid(row=2, column=0)
            radio_switch_2.grid(row=2, column=1)
            radio_switch_3.grid(row=2, column=2)
            radio_switch_4.grid(row=2, column=3)
            label_split_by_entry.grid(row=3, column=2)
            entry_split_by.grid(row=3, column=3)
            strip_chbx.grid(row=4, column=1, columnspan=1)

            frame[1].pack()
            logging.info(f"Unhidden")
        
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

        sep_label = tk.Label(frame[1], text="\nSeperator:", background= "white")
        radio_switch_1 = tk.Radiobutton(frame[1], text = "'\\n'", variable = split_by,
                                        value = "\n")#, background= "white")
        radio_switch_2 = tk.Radiobutton(frame[1], text = "', '", variable = split_by,
                                        value = ",")#, background= "white")
        radio_switch_3 = tk.Radiobutton(frame[1], text = "'\\t'", variable = split_by,
                                        value = "\t")#, background= "white")
        radio_switch_4 = tk.Radiobutton(frame[1], text = "' '", variable = split_by,
                                        value = " ")#, background= "white")
        label_split_by_entry = tk.Label(frame[1], text = "Other:")
        entry_split_by = tk.Entry(frame[1], textvariable=split_by)

        case_chbx = tk.Checkbutton(frame[1], text="Case Sensitive", variable=case_sensitive)
        strip_chbx = tk.Checkbutton(frame[1], text="Strip Excess Space", variable=strip)
        difflib_chbx = tk.Checkbutton(frame[1], text="Use Difflib Algo", variable=use_diff)
        case_chbx.grid(row=4, column=0, columnspan=1)
        difflib_chbx.grid(row=4, column=2)
        #difflib_chbx.bind("<Button-1>", hide_all)
        difflib_trace = use_diff.trace("w", hide_all)

        compare_button = tk.Button(frame[1], text="Compare", command=compare)
        compare_button.grid(row=5, column=0, columnspan=4)

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

        sep_label = tk.Label(frame[0], text="\nSeperator:", background= "white")
        radio_switch_1 = tk.Radiobutton(frame[0], text = "'\\n'", variable = split_by,
                                        value = "\n")#, background= "white")
        radio_switch_2 = tk.Radiobutton(frame[0], text = "', '", variable = split_by,
                                        value = ",")#, background= "white")
        radio_switch_3 = tk.Radiobutton(frame[0], text = "'\\t'", variable = split_by,
                                        value = "\t")#, background= "white")
        radio_switch_4 = tk.Radiobutton(frame[0], text = "' '", variable = split_by,
                                        value = " ")#, background= "white")

        sep_label.grid(row=2, column=0)
        radio_switch_1.grid(row=3, column=0)
        radio_switch_2.grid(row=3, column=1)
        radio_switch_3.grid(row=3, column=2)
        radio_switch_4.grid(row=3, column=3)

        case_chbx = tk.Checkbutton(frame[0], text="Case Sensitive", variable=case_sensitive)
        strip_chbx = tk.Checkbutton(frame[0], text="Strip Excess Space", variable=strip)
        case_chbx.grid(row=4, column=0, columnspan=2)
        strip_chbx.grid(row=4, column=2, columnspan=2)

        compare_button = tk.Button(frame[0], text="Compare", command=compare)
        compare_button.grid(row=5, column=0, columnspan=4)

        text_1_label_2 = tk.Label(frame[1], text="Text #1 Unique", background="white")
        text_1_label_2.grid(row=0, column=0)
        text_2_label_2 = tk.Label(frame[1], text="Text #2 Unique", background="white")
        text_2_label_2.grid(row=0, column=1)

        text_1_disp = tk.Text(frame[1], background="lightgrey", height=5)
        text_1_disp.grid(row=1, column=0)
        text_2_disp = tk.Text(frame[1], background="lightgrey", height=5)
        text_2_disp.grid(row=1, column=1)

        dupe_label = tk.Label(frame[1], text="Duplicates", background="white")
        dupe_label.grid(row=2, column=0, columnspan=2)

        dupe_entry = tk.Text(frame[1], background="lightgrey", height=5, width=160)
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

        radio_switch_1 = tk.Radiobutton(frame[1], text = "Regex", variable = regex,
                                        value = 1, background= "white")
        radio_switch_2 = tk.Radiobutton(frame[1], text = "Standard", variable = regex,
                                        value = 0, background= "white")
        radio_switch_1.grid(row=0, column=0)
        radio_switch_2.grid(row=0, column=1)

        find_label = tk.Label(frame[1], text="Find:", background="white") 
        replace_label = tk.Label(frame[1], text="Replace With:", background="white") 
        find_label.grid(row=1, column=0)
        replace_label.grid(row=1, column=1)

        entry_find = tk.Entry(frame[1], textvariable=find_this, width=25)
        entry_find.grid(row=2, column=0)
        entry_replace = tk.Entry(frame[1], textvariable=replace_w_this, width=25)
        entry_replace.grid(row=2, column=1)

        run_button = tk.Button(frame[1], width=45, height=5, text="Run", command=run)
        run_button.grid(column=3, row=0, rowspan=3)

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
            self.combiner()
            logging.info(f"Reset")

        def show_value():
            sep = str(seperator.get())
            outcome= sep.join(clipboard)
            messagebox.showinfo(title="Result", message=outcome)
            logging.info(f"Showing")

        play_button = tk.Button(frame[0], text="Play", command=get_clips, width = 10)
        pause_button = tk.Button(frame[0], text="Reset", command=reset, width = 10)
        copy_button = tk.Button(frame[0], text="Copy", command = copy_value, width = 10)
        show_button = tk.Button(frame[0], text="Show", command = show_value, width = 10)
        radio_switch_1 = tk.Radiobutton(frame[0], text = "'\\n'", variable = seperator,
                                        value = "\n", background= "white")
        radio_switch_2 = tk.Radiobutton(frame[0], text = "', '", variable = seperator,
                                        value = ", ", background= "white")
        radio_switch_3 = tk.Radiobutton(frame[0], text = "'\\t'", variable = seperator,
                                        value = "\t", background= "white")
        radio_switch_4 = tk.Radiobutton(frame[0], text = "' '", variable = seperator,
                                        value = " ", background= "white")
        sep_label = tk.Label(frame[0], text="\nSeperator:", background= "white")

        play_button.grid(row=0, column=0)
        pause_button.grid(row=0, column=1)
        copy_button.grid(row=0, column=2)
        show_button.grid(row=0, column=3)
        sep_label.grid(row=1, column=0)
        radio_switch_1.grid(row=2, column=0)
        radio_switch_2.grid(row=2, column=1)
        radio_switch_3.grid(row=2, column=2)
        radio_switch_4.grid(row=2, column=3)

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
                config = configparser.ConfigParser()
                try: config.read("localonly.SOCer.config")
                except: config.read("SOCer.config")
                key = config["DEFAULT"]["virus_total_key"]
                
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

        decode_button = tk.Button(frame[2], width=20, text="Decode", command=decode)
        decode_button.grid(column=0, row=2, rowspan=1)
        vt_button = tk.Button(frame[2], width=20, text="VirusTotal", command=vt_scan)
        vt_button.grid(column=1, row=2, rowspan=1)

#Run code.
x = SOCer()


