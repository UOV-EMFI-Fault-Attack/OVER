import os
import ctypes
import time
from random import randbytes

current_dir = os.path.dirname(os.path.abspath(__file__))
library_path = os.path.join(current_dir, "build")
shared_lib = ctypes.CDLL(os.path.join(library_path, "validation_functions-test.so"))

if __name__ == '__main__':
    # Generated faulted signatures in a row
    # signature buffer is zeroed before every run and therefore known
    while True:
        msg = bytes.fromhex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        sig_len = 128
        
        shared_lib.generate_faulted_sig.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),  # m
            ctypes.POINTER(ctypes.c_ubyte),  # sm
            ctypes.POINTER(ctypes.c_ubyte),  # salt (random if NULL)
            ctypes.POINTER(ctypes.c_ubyte),  # out
        ]
        shared_lib.generate_faulted_sig.restype = ctypes.c_int

        msg_ctype = (ctypes.c_ubyte * len(msg)).from_buffer_copy(msg) # use message from target
        sm_ctype = (ctypes.c_ubyte * (len(msg) + sig_len)).from_buffer_copy(msg + b'\x00' * sig_len) # zeroed out signature
        sig_out = (ctypes.c_ubyte * sig_len)()
        

        shared_lib.generate_faulted_sig(msg_ctype, sm_ctype, None, sig_out)
        
        print(bytes(sig_out).hex().upper())
        time.sleep(1)

