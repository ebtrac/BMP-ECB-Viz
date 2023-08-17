from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers import BlockCipherAlgorithm, CipherAlgorithm
import tkinter as tk
from tkinter import ttk, filedialog
from PIL import Image, ImageTk
import os
import math
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
        algorithm_combobox.bind('<<ComboboxSelected>>', self.algorithm_update)
        
        # key label and text
        keylbl = ttk.Label(self.control_frame, text='Key')
        self.key_text = tk.Text(self.control_frame, wrap='char', height=3, width=32)
        
        # bind function to fire when the key changes
        self.key_text.bind("<<Modified>>", self.algorithm_update)
        
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

    def generate_random_key(self):
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
        outputfilebytes = self.converter.convert(self.inputfilebytes)
        self.pil_img_out = Image.frombytes(mode='RGB', size=self.pil_img_in.size, data=outputfilebytes).transpose(Image.Transpose.FLIP_TOP_BOTTOM)
            
    def algorithm_update(self, *args):
        if self.algorithmvar.get() == 'None':
            self.randkeysize_combobox.config(values=[])
            self.randkeysize_combobox.set('')
            self.process_img()
            self.set_img()
            return
        
        # check the textbox modified flag
        if self.key_text.edit_modified() == True:
            self.key_text.edit_modified(False)
        
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
        
if __name__ == '__main__':
    app = App()
    app.mainloop()
