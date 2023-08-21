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
        algorithm_combobox = ttk.Combobox(
            self.control_frame,
            textvariable=self.algorithmvar,
            state='readonly'
        )
        
        # set defualt values for the algorithms combobox
        algo_values = ('None',)
        algo_names = list(self.algodict.keys())
        algo_names.sort()
        algo_names = tuple(algo_names)
        algo_values = algo_values + algo_names
        algorithm_combobox.config(values=algo_values)
        algorithm_combobox.current(0)
        # place algorithms label and combobox
        algorithm_lbl.grid(row=0, column=0, sticky='nw')
        algorithm_combobox.grid(row=0, column=1, sticky='nw')
        
        # bind function to fire when algorithm changes
        algorithm_combobox.bind('<<ComboboxSelected>>', self.algorithm_combobox_changed)
        
        # key label and text
        keylbl = ttk.Label(self.control_frame, text='Key')
        self.key_text = tk.Text(self.control_frame, wrap='char', height=3, width=32)
        
        # bind function to fire when the key changes
        self.key_text.bind("<<Modified>>", self.key_changed)
        
        # place key label and text
        keylbl.grid(row=1, column=0, sticky='nw')
        self.key_text.grid(row=2,column=0, columnspan=3, padx=5, pady=5, sticky='ns')
        
        # random key generator button
        randkeybtn = ttk.Button(self.control_frame, text='Random Key', command=self.generate_random_key)
        # random key size combobox
        randkeysizelbl = ttk.Label(self.control_frame, text='Key Size (bits)')
        self.keysizevar = tk.StringVar()
        self.randkeysize_combobox = ttk.Combobox(self.control_frame, textvariable=self.keysizevar, state='readonly')
        
        # place random key generator controls and labels
        randkeysizelbl.grid(row=3, column=0, sticky='nw')
        self.randkeysize_combobox.grid(row=3,column=1, sticky='nw')
        randkeybtn.grid(row=3, column=2, )
        
        # place increment and decrement key buttons
        inckey_btn = ttk.Button(self.control_frame, text='Key++', command=self.increment_key)
        deckey_btn = ttk.Button(self.control_frame, text='Key--', command=self.decrement_key)
        inckey_btn.grid(row=4, column=0, sticky='nw')
        deckey_btn.grid(row=4, column=1, sticky='nw')
        
        # block size selection controls and labels
        # blocksizelbl = ttk.Label(self.control_frame, text='Block Size')
        self.blocksizevar = tk.StringVar()
        self.blocksize_spinbox = ttk.Spinbox(self.control_frame, from_=1.0, to=1024.0, textvariable=self.blocksizevar)
        # # place blocksize controls and labels
        # blocksizelbl.grid(row=4, column=0, sticky='nw')
        # self.blocksize_spinbox.grid(row=4, column=1, sticky='nw')
        
        # self.blocksize_spinbox.bind('<KeyRelease>', self.blocksize_changed)
        # self.blocksize_spinbox.bind('<<Decrement>>', self.blocksize_changed)
        # self.blocksize_spinbox.bind('<<Increment>>', self.blocksize_changed)
        
        # place nonce input controls
        noncelbl = ttk.Label(self.control_frame, text='Nonce')
        self.noncevar = tk.StringVar()
        self.nonce_entry = ttk.Entry(self.control_frame, textvariable=self.noncevar, width=32)
        self.randnoncebtn = ttk.Button(self.control_frame, text='Random Nonce', command=self.generate_random_nonce)
        noncelbl.grid(row=5, column=0, sticky='nw')
        self.nonce_entry.grid(row=6, column=0, columnspan=2, padx=5, sticky='nw')
        self.randnoncebtn.grid(row=6, column=2, sticky='nw')
        
        # DEBUG place debug controls
        self.debug_actualkeyvar = tk.StringVar()
        debug_actualkey_entry = ttk.Entry(self.control_frame, textvariable=self.debug_actualkeyvar, width=48, state='readonly')
        debug_refreshactualkey = ttk.Button(self.control_frame, text='refresh actual key', command=self.debug_refreshactualkey)
        debug_actualkey_entry.grid(row=10, column=0, columnspan=2, sticky='nw')
        debug_refreshactualkey.grid(row=11, column=0)
        
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

    def generate_random_nonce(self, *args):
        nonce = os.urandom(16) # 16 bytes, 128 bits
        self.nonce_entry.delete(0, tk.END)
        self.nonce_entry.insert(0, nonce.hex())

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
        resized_img = self.pil_img_out.resize((self.canvas.winfo_width(), self.canvas.winfo_height()))
        self.img = ImageTk.PhotoImage(image=resized_img)
        self.bg = self.canvas.create_image(0,0,anchor=tk.NW, image=self.img)
    
    def process_img(self, *args):
        """ processes the image using selected settings """
        if self.algorithmvar.get() == 'None':
            self.pil_img_out = self.pil_img_in.copy()
            return

        # handle padding of input to be multiple of block size
        # paddedinputfilebytes = bytearray(self.inputfilebytes)
        # try:
        #     blocksize = int(self.blocksizevar.get())
        # except ValueError:
        #     blocksize = 8
        # while len(paddedinputfilebytes) % blocksize != 0:
        #     paddedinputfilebytes.append(0)
        # paddedinputfilebytes = bytes(paddedinputfilebytes)
        # outputfilebytes = self.converter.convert(paddedinputfilebytes)
        outputfilebytes = self.converter.convert(self.inputfilebytes)
        self.pil_img_out = Image.frombytes(mode='RGB', size=self.pil_img_in.size, data=outputfilebytes).transpose(Image.Transpose.FLIP_TOP_BOTTOM)
    
    def blocksize_changed(self, *args):
        print('blocksize changed', self.blocksizevar.get())
        if self._key_exists():
            if self.blocksizevar.get() != '' and self.blocksizevar.get().isnumeric():
                self.algo.block_size = int(self.blocksizevar.get())
                self.converter.set_algorithm(self.algo)
                self.process_img()
                self.set_img()
    
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
            if self.algoclass == algorithms.ChaCha20:
                self.algo = self.algoclass(bytes.fromhex(self._key_wrangle()), bytes.fromhex(self._nonce_wrangle()))
            else:
                self.algo = self.algoclass(bytes.fromhex(self._key_wrangle()))
            self.converter.set_algorithm(self.algo)
            # DEBUG
            self.debug_refreshactualkey()
            self.process_img()
            self.set_img()
    
    def algorithm_combobox_changed(self, *args):
        """fires when the algorithm combobox has been selected/modified"""
        new_algo = self.algorithmvar.get()
        if new_algo == 'None':
            self.randkeysize_combobox.config(values=[])
            self.randkeysize_combobox.set('')
            self.process_img()
            self.set_img()
            return
        
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
        self.randkeysize_combobox.config(values=key_sizes_str)
        # self.randkeysize_combobox.current(0) # select first value
        
        if issubclass(NewAlgoClass, BlockCipherAlgorithm):
            """handle block cipher settings configuration"""
            self.blocksize_spinbox.config(state='normal')
            # set to default value for the algorithm
            self.blocksizevar.set(str(NewAlgoClass.block_size))
        else:
            """disable block cipher settings"""
            self.blocksize_spinbox.config(state='disabled')
        
        # enable or disable the nonce entry and button
        if NewAlgoClass == algorithms.ChaCha20:
            self.nonce_entry.config(state='normal')
            self.randnoncebtn.config(state='normal')
        else:
            self.nonce_entry.config(state='disabled')
            self.randnoncebtn.config(state='disabled')
            
        
        # if a key exists, instantiate the algorithm with the key
        if self._key_exists():
            if self.algoclass == algorithms.ChaCha20:
                self.algo = self.algoclass(bytes.fromhex(self._key_wrangle()), bytes.fromhex(self._nonce_wrangle()))
            else:
                self.algo = self.algoclass(bytes.fromhex(self._key_wrangle()))
            self.converter.set_algorithm(self.algo)
            # DEBUG
            self.debug_refreshactualkey()
            self.process_img()
            self.set_img()
                   
    def algorithm_update(self, *args):
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
        print(args[0])
        
        if self.algorithmvar.get() == 'None':
            self.randkeysize_combobox.config(values=[])
            self.randkeysize_combobox.set('')
            self.process_img()
            self.set_img()
            return
        
        
        
        # TODO based on the algorithmvar, use appropriate block sizes, key sizes, etc
        AlgClass = self.algodict[self.algorithmvar.get()]
        
        # update keysizes
        key_sizes = list(AlgClass.key_sizes)
        key_sizes.sort() # sort values ascending
        key_sizes_str = [str(size) for size in key_sizes]
        self.randkeysize_combobox.config(values=key_sizes_str)
        # self.randkeysize_combobox.current(0) # select first value
        
        
        if issubclass(AlgClass, BlockCipherAlgorithm):
            """handle block cipher settings configuration"""
        else:
            """disable block cipher settings"""
        
        if self.key_text.count(1.0, tk.END, 'chars')[0] > 1:
            key = self.key_text.get(1.0, tk.END)
            key = key.replace('\n','')
            if not key:
                return
            if len(key) % 2 != 0:
                key = '0'+key
            key = bytes.fromhex(str(key))
            # limit size to maximum key size
            if 8*len(key) > max(key_sizes):
                key = bytes.fromhex(hex(int(key.hex(), 16) & (2**max(key_sizes)-1))[2:])
                self.randkeysize_combobox.current(len(key_sizes)-1)
            elif 8*len(key) not in key_sizes:
                i = 0
                if 8*len(key) < min(key_sizes):
                    appropriate_size = min(key_sizes)
                else:
                    for size in key_sizes:
                        if 8*len(key) < size:
                            i += 1
                            continue
                        appropriate_size = size
                        break
                # pad with zeros
                n_pad_bytes = appropriate_size//8 - len(key)
                key = bytearray(key)
                key = list(key)
                key = n_pad_bytes*[0] + key
                key = bytes(key)
                self.randkeysize_combobox.current(i)
            algo = AlgClass(key)
            self.converter.set_algorithm(algo)
            self.process_img()
        self.set_img()
    
    def debug_refreshactualkey(self, *args):
        if self._key_exists():
            self.debug_actualkeyvar.set(self._key_wrangle())
    
    def _nonce_wrangle(self) -> str:
        """ returns a nonce from the text """
    
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
