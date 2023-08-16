from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers import (
    BlockCipherAlgorithm,
    CipherAlgorithm,
)


class BMP2ECB:
    def __init__(self, algorithm: BlockCipherAlgorithm | CipherAlgorithm | None = None, mode: modes.Mode() = modes.ECB()):
        self.algorithm = algorithm
        self.mode = mode
        self.cipher = None
        self.encryptor = None
        
        if issubclass(self.algorithm, (BlockCipherAlgorithm, CipherAlgorithm)) and issubclass(self.mode, modes.Mode):
            self.set_algorithm(self.algorithm, self.mode)
        
    def __getheader(self, data : bytes, n=54) -> bytes:
        return data[:n]
    
    def convert(self, img : bytes, headerlen=54) -> bytes:
        if self.algorithm is None:
            raise Exception('Algorithm is not set. Use set_algorithm() to select an algorithm.')
        header = self.__getheader(img, n=headerlen)
        ct = self.encryptor.update(img)
        ct = bytearray(ct)
        ct[:headerlen] = header
        return bytes(ct)
    
    def set_algorithm(self, algorithm: BlockCipherAlgorithm | CipherAlgorithm, mode: modes.Mode() = modes.ECB()):
        self.algorithm = algorithm
        self.mode = mode
        self.cipher = Cipher(self.algorithm, self.mode)
        self.encryptor = self.cipher.encryptor()
        
    def print_algorithms(self):
        blockciphers = [cls.__name__ for cls in BlockCipherAlgorithm.__subclasses__()]
        ciphers = [cls.__name__ for cls in CipherAlgorithm.__subclasses__()]
        print("Block Cipher Algorithms:")
        for name in blockciphers:
            print(' '+name)
        print("Cipher Algorithms:")
        for name in ciphers:
            print(' '+name)
        