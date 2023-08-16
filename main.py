from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

filename = 'ecb-test-star.bmp'
outfilename = 'output-'+filename

# open the bmp
with open(filename, 'rb') as f:
    # read the 54 byte header
    header = f.read(54)

    # reset reader position
    f.seek(0)

    # generate a key
    key = 40*b'5'

    # choose algorithm
    algo = algorithms.Blowfish(key)

    # make cipher object in ECB mode
    cipher = Cipher(algo, modes.ECB())

    # create encryptor
    encryptor = cipher.encryptor()

    # generate ciphertext from encryptor 
    ct = encryptor.update(f.read())
    
# convert to bytearray to make the cyphertext mutable
ct = bytearray(ct)

# replace the first 54 bytes of cipher text with the original header
ct[:54] = header

# convert back to bytes
ct = bytes(ct)
    
# create/open the output bmp
with open(outfilename, 'xb') as f:
    # write the cyphertext to a file
    f.write(ct)
