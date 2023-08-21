from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers import BlockCipherAlgorithm, CipherAlgorithm
import tkinter as tk
from tkinter import ttk, filedialog
from PIL import Image, ImageTk
import os
import math
import re
from BMP2ECB import BMP2ECB

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.resizable(1,1)
        self.title('BMP to ECB')
        self.geometry('800x400')
                
        # instantiate the BMP2ECB class
        self.converter = BMP2ECB()

        # algorithms and their associated classes
        self.algodict = dict()
        for cls in BlockCipherAlgorithm.__subclasses__():
            self.algodict[cls.__name__] = cls
        for cls in CipherAlgorithm.__subclasses__():
            if cls is not BlockCipherAlgorithm:
                self.algodict[cls.__name__] = cls
        # remove ARC4 because it doesnt support ECB
        self.algodict.pop('ARC4')
        # remove ChaCha20 because it doesnt support ECB
        self.algodict.pop('ChaCha20')    
        # remove redundant entries of AES
        self.algodict.pop('AES128')
        self.algodict.pop('AES256')
        
        # contains the selected keysizes for each of the algorithms
        self.keysize_settings = dict()
        for key in self.algodict.keys():
            # initialize settings with all selections being the first in list of possible key sizes
            self.keysize_settings[key] = 0
        
        self.algo = None
        self.algoclass = None
        
        # menu bar
        menubar = tk.Menu(self)
        self.menu_file = tk.Menu(menubar, tearoff=False)
        menubar.add_cascade(menu=self.menu_file, label='File')
        self.menu_file.add_command(label='Open...', command=self.select_file, accelerator='Ctrl+O')
        self.menu_file.add_command(label='Save As...', command=self.save_file, accelerator='Ctrl+S', state='disabled')
        self.config(menu=menubar)
        
        # keybindings
        self.bind_all("<Control-o>", self.select_file)
        self.bind_all("<Control-s>", self.save_file)
        
        # control frame
        self.control_frame = ttk.Frame(self)
        
        # algorithms
        algorithm_lbl = ttk.Label(self.control_frame, text='Algorithm')
        self.algorithmvar = tk.StringVar()
        self.algorithm_combobox = ttk.Combobox(
            self.control_frame,
            textvariable=self.algorithmvar,
            state='disabled'
        )
        
        # set defualt values for the algorithms combobox
        algo_values = ('None',)
        algo_names = list(self.algodict.keys())
        algo_names.sort()
        algo_names = tuple(algo_names)
        algo_values = algo_values + algo_names
        self.algorithm_combobox.config(values=algo_values, state='disabled')
        self.algorithm_combobox.current(0)
        # place algorithms label and combobox
        algorithm_lbl.grid(row=0, column=0, sticky='nw')
        self.algorithm_combobox.grid(row=0, column=1, sticky='nw')
        
        # bind function to fire when algorithm changes
        self.algorithm_combobox.bind('<<ComboboxSelected>>', self.algorithm_combobox_changed)
        
        # key label and text
        keylbl = ttk.Label(self.control_frame, text='Key')
        self.key_text = tk.Text(self.control_frame, wrap='char', height=3, width=32, state='disabled')
        
        # bind function to fire when the key changes
        self.key_text.bind("<<Modified>>", self.key_changed)
        
        # place key label and text
        keylbl.grid(row=1, column=0, sticky='nw')
        self.key_text.grid(row=2,column=0, columnspan=3, padx=5, pady=5, sticky='ns')
        
        # random key generator button
        self.randkey_btn = ttk.Button(self.control_frame, text='Random Key', command=self.generate_random_key, state='disabled')
        # random key size combobox
        randkeysizelbl = ttk.Label(self.control_frame, text='Key Size (bits)')
        self.keysizevar = tk.StringVar()
        self.keysize_combobox = ttk.Combobox(self.control_frame, textvariable=self.keysizevar, state='disabled')
        
        self.keysize_combobox.bind('<<ComboboxSelected>>', self.keysize_changed)
        
        # place random key generator controls and labels
        randkeysizelbl.grid(row=3, column=0, sticky='nw')
        self.keysize_combobox.grid(row=3,column=1, sticky='nw')
        self.randkey_btn.grid(row=3, column=2, )
        
        # place increment and decrement key buttons
        self.inckey_btn = ttk.Button(self.control_frame, text='Key++', command=self.increment_key, state='disabled')
        self.deckey_btn = ttk.Button(self.control_frame, text='Key--', command=self.decrement_key, state='disabled')
        self.inckey_btn.grid(row=4, column=0, sticky='nw')
        self.deckey_btn.grid(row=4, column=1, sticky='nw')

        # place popout preview controls
        self.popout_btn = ttk.Button(self.control_frame, text='Popout Preview', command=self.create_image_popup, state='disabled')
        self.popout_btn.grid(row=50, column=0, sticky='nw', pady=10)

        # DEBUG place debug controls
        self.debug_actualkeyvar = tk.StringVar()
        ttk.Label(self.control_frame, text='Actual Key').grid(row=9, column=0, sticky='nw')
        debug_actualkey_entry = ttk.Entry(self.control_frame, textvariable=self.debug_actualkeyvar, width=48, state='disabled')
        debug_refreshactualkey_btn = ttk.Button(self.control_frame, text='refresh actual key', command=self.debug_refreshactualkey, state='disabled')
        debug_actualkey_entry.grid(row=10, column=0, columnspan=3, sticky='nw')
        # debug_refreshactualkey.grid(row=11, column=0)
        
        # place the control frame
        self.control_frame.grid(row=0, column=0, sticky='nsw')
        
        # picture frame
        self.picture_frame = ttk.Frame(self)
        self.picture_frame.rowconfigure(0, weight=1)
        self.picture_frame.columnconfigure(0, weight=1)
        # canvas
        self.canvas = tk.Canvas(self.picture_frame, width=400,height=400)
        self.canvas.grid(row=0,column=0, sticky='nsew')
        
        # place picture frame
        self.picture_frame.grid(row=0,column=1, sticky='nsew')
     
    def create_image_popup(self, *args):
        self.popout_btn.config(state='disabled')
        self.popup = tk.Toplevel()
        self.popup.title('Image Viewer')
        self.popup_photo = ImageTk.PhotoImage(self.pil_img_out)
        # create a label to show the image
        self.popup_label = tk.Label(self.popup, image=self.popup_photo)
        self.popup_label.pack(expand=True, fill='both')
        
        self.popup_label.image = self.popup_photo
        
        self.popup.update_idletasks()
        # centers the image on the screen
        self.popup.geometry(f"+{self.popup.winfo_screenwidth() // 2 - self.popup.winfo_width() // 2}+{self.popup.winfo_screenheight() // 2 - self.popup.winfo_height() // 2}")
        # disable resizing because it causes inflation
        # self.popup.bind('<Configure>', self.resizepopup)
        
        self.popup.protocol("WM_DELETE_WINDOW", self.close_image_popup)

    def close_image_popup(self, *args):
        self.popout_btn.config(state='normal')
        self.popup.destroy()

    def resizepopup(self, event):
        new_w,new_h = event.width, event.height
        print('resizing')
        original_w, original_h = self.pil_img_out.size
        aspect_ratio = original_w/original_h
        if aspect_ratio > 1:
            # landscape
            new_h = round(new_w/aspect_ratio)
        else:
            # portrait
            new_w = round(new_h * aspect_ratio)
        self.popup.unbind('<Configure>')
        self.popup_photo = ImageTk.PhotoImage(self.pil_img_out.resize((new_w, new_h)))
        self.popup_label.config(image=self.popup_photo)
        self.popup_label.image = self.popup_photo
        self.popup.bind('<Configure>', self.resizepopup)
        
        
    def select_file(self, *args):
        filetypes = (
            ('Bitmap files', '*.bmp'),
            ('All files', '*.*')
        )
        
        inputfile = filedialog.askopenfile(
            mode='rb',
            filetypes=filetypes
        )
        
        if inputfile is None:
            return
        
        self.pil_img_in = Image.open(inputfile)
        self.pil_img_out = self.pil_img_in.copy()
        
        inputfile.seek(0)
        self.inputfilebytes = inputfile.read()
        inputfile.close()
        
        # enable saving
        self.menu_file.entryconfig('Save As...', state='normal')
        
        # enable algorithm combobox
        self.algorithm_combobox.config(state='readonly')
        # enable image popout button
        self.popout_btn.config(state='normal')
        
        # show the image
        self.set_img()
    
    def save_file(self, *args):
        filetypes = (
            ('Bitmap files', '*.bmp'),
            ('All files', '*.*')
        )
        
        outputfile = filedialog.asksaveasfile(
            mode='wb',
            filetypes=filetypes,
            confirmoverwrite=True,
            defaultextension='.bmp'
        )
        
        self.pil_img_out.save(outputfile)
        
        outputfile.close()

    def increment_key(self, *args):
        if self._key_exists():
            key = self._key_wrangle()
            keyint = int(key, 16) + 1
            newkey = hex(keyint)[2:]
            if len(newkey) > len(key):
                newkey = newkey[1:]
            elif len(newkey) < len(key):
                newkey = '0'*(len(key) - len(newkey)) + newkey
            self.key_text.delete(1.0, tk.END)
            self.key_text.insert(1.0, newkey)
        else:
            keysize = int(self.keysize_combobox.get()) // 8
            newkey = '0'*keysize
            self.key_text.delete(1.0, tk.END)
            self.key_text.insert(1.0, newkey)
            
    def decrement_key(self, *args):
        if self._key_exists():
            key = self._key_wrangle()
            keyint = int(key, 16) - 1
            if keyint < 0:
                keyint = 2**int(self.algo.key_size) - 1
            newkey = hex(keyint)[2:]
            if len(newkey) > len(key):
                newkey = newkey[1:]
            elif len(newkey) < len(key):
                newkey = '0'*(len(key) - len(newkey)) + newkey
            self.key_text.delete(1.0, tk.END)
            self.key_text.insert(1.0, newkey)
        else:
            keysize = int(self.keysize_combobox.get()) // 8
            newkey = '0'*keysize
            self.key_text.delete(1.0, tk.END)
            self.key_text.insert(1.0, newkey)

    def generate_random_key(self, *args):
        if self.keysizevar.get() == '':
            return
        
        # keysize in bits
        keysize = int(self.keysizevar.get())
                
        key = os.urandom(math.ceil(keysize/8))
        
        self.key_text.delete(1.0, tk.END)
        self.key_text.insert(1.0, key.hex())
    
    def set_img(self):
        """ set the processed image to the canvas """
        self.popup_photo = ImageTk.PhotoImage(self.pil_img_out)
        try:
            self.popup_label.config(image=self.popup_photo)
            self.popup_label.image = self.popup_photo
        except:
            pass
        resized_img = self.pil_img_out.resize((self.canvas.winfo_width(), self.canvas.winfo_height()))
        self.img = ImageTk.PhotoImage(image=resized_img)
        self.bg = self.canvas.create_image(0,0,anchor=tk.NW, image=self.img)
    
    def process_img(self, *args):
        """ processes the image using selected settings """
        if self.algorithmvar.get() == 'None':
            self.pil_img_out = self.pil_img_in.copy()
            return
        
        # print('image processed', self.converter.algorithm.key.hex())
        outputfilebytes = self.converter.convert(self.inputfilebytes)
        self.pil_img_out = Image.frombytes(mode='RGB', size=self.pil_img_in.size, data=outputfilebytes).transpose(Image.Transpose.FLIP_TOP_BOTTOM)
    
    def key_changed(self, *args):
        event = None
        if args:
            event = args[0]
        
        # check the textbox modified flag
        if self.key_text.edit_modified() == True:
            self.key_text.edit_modified(False)
        else:
            if event:
                if 'text' in event.widget.widgetName:
                    return
    
        # if a key exists, instantiate the algorithm with the key
        if self._key_exists():
            self.algo = self.algoclass(bytes.fromhex(self._key_wrangle()))
            self.converter.set_algorithm(self.algo)
            self.process_img()
            self.set_img()
            # DEBUG
            self.debug_refreshactualkey()
    
    def keysize_changed(self, *args):
        # update keysize setting for this algorithm
        current_algo = self.algorithmvar.get()
        self.keysize_settings[current_algo] = self.keysize_combobox.current()
        
          # if a key exists, instantiate the algorithm with the key
        if self._key_exists():
            self.algo = self.algoclass(bytes.fromhex(self._key_wrangle()))
            self.converter.set_algorithm(self.algo)
            self.process_img()
            self.set_img()
            # DEBUG
            self.debug_refreshactualkey()
    
    def algorithm_combobox_changed(self, *args):
        """fires when the algorithm combobox has been selected/modified"""
        new_algo = self.algorithmvar.get()
        if new_algo == 'None':
            self.keysize_combobox.config(values=[])
            self.keysize_combobox.set('')
            self.algoclass = None
            # disable all controls except algorithm combobox
            ctlstate = 'disabled'
            self.key_text.config(state=ctlstate)
            self.keysize_combobox.config(state=ctlstate)
            self.deckey_btn.config(state=ctlstate)
            self.inckey_btn.config(state=ctlstate)
            self.randkey_btn.config(state=ctlstate)
            
            self.process_img()
            self.set_img()
            return
        
        # enable all controls
        ctlstate = 'normal'
        self.keysize_combobox.config(state='readonly')
        self.key_text.config(state=ctlstate)
        self.deckey_btn.config(state=ctlstate)
        self.inckey_btn.config(state=ctlstate)
        self.randkey_btn.config(state=ctlstate)
        
        NewAlgoClass = self.algodict[new_algo]
        
        # return if the current algorithm matches the one that is selected
        if NewAlgoClass == self.algoclass:
            return
        
        # store the new class
        self.algoclass = NewAlgoClass
        
        # update keysizes
        key_sizes = list(NewAlgoClass.key_sizes)
        key_sizes.sort() # sort values ascending
        key_sizes_str = [str(size) for size in key_sizes]
        if NewAlgoClass == algorithms.AES:
            key_sizes_str.pop() # remove 512 from the list of sizes. not supported for ECB mode
        self.keysize_combobox.config(values=key_sizes_str)
        # load keysize setting for this algorithm
        self.keysize_combobox.current(self.keysize_settings[new_algo])
                
        # if a key exists, instantiate the algorithm with the key
        if self._key_exists():
            self.algo = self.algoclass(bytes.fromhex(self._key_wrangle()))
            self.converter.set_algorithm(self.algo)
            # DEBUG
            self.debug_refreshactualkey()
            self.process_img()
            self.set_img()
    
    def debug_refreshactualkey(self, *args):
        if self._key_exists():
            self.debug_actualkeyvar.set(self._key_wrangle())

    def _key_wrangle(self) -> str:
        """ returns a key from the text """
        keystr = self.key_text.get(1.0, tk.END)
        try:
            keysize = int(self.keysizevar.get())
            keysize = int(keysize/8) * 2 # number of hex characters the key must be
        except ValueError:
            # the keysize has not been selected, get default size
            keysize = int(list(self.algodict[self.algorithmvar.get()].key_sizes)[0]/8) * 2
            
        # remove newlines
        keystr = keystr.replace('\n', '')
        
        if keystr == '':
            return keysize*'0'
        
        # insert a 0 if the length of the key is odd
        if len(keystr) % 2 != 0:
            keystr = '0'+keystr
        
        # attempt to interpret as a hex value
        try:
            key = bytes.fromhex(keystr)
        except ValueError: # cant interpret as hex
            # strip all whitespace
            keystr = re.sub('[\s*]', '', keystr)
                
            # convert all nonhex chars to their hex representations
            newkeystr = list(keystr)
            nonhexiter = re.finditer('[^a-fA-F0-9]', keystr)
            # create a list of the indices for each match
            matchind = [m.start() for m in nonhexiter]
            # reverse it so we can modify the keystr from end to beginning, preserving validity of lower indices
            matchind.reverse()
            for i in matchind:
                hexstr = hex(ord(keystr[i]))[2:] # remove the leading 0x
                # insert a 0 if the length is odd
                if len(hexstr) % 2 != 0:
                    hexstr = '0' + hexstr
                
                # remove the non-hex value from the newkeystr
                newkeystr.pop(i)
                # insert the hex value in place of the non-hex value
                newkeystr.insert(i, hexstr)
            # convert the newkeystr back to a string
            keystr = ''.join(newkeystr)
        
        if len(keystr) < keysize:
            # prepend zeros
            return '0'*(keysize - len(keystr)) + keystr
        elif len(keystr) > keysize:
            return keystr[(len(keystr) - keysize):]
        else:
            return keystr
                
    def _key_exists(self):
        """ returns true if text exists in the key_text widget """
        return (self.key_text.count(1.0, tk.END, 'chars')[0] > 1)
       
if __name__ == '__main__':
    app = App()
    app.mainloop()
