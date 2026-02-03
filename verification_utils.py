import os
import ctypes


current_dir = os.path.dirname(os.path.abspath(__file__))
library_path = os.path.join(current_dir, "build")
shared_lib = ctypes.CDLL(os.path.join(library_path, "validation_functions-test.so"))

def verify_signature(msg: bytes, sig: bytes) -> int:
    """
    Verify signature with shared library.

    Args:
        msg (bytes): Message (256 bytes)
        sig (bytes): Signature (128 bytes)

    Returns:
        int:
            - `0` if valid
            - `1` if invalid
            - `-1` if error occurred in shared library
    """
    if (len(msg) != 256):
        raise ValueError("Invalid msg length")
    if (len(sig) != 128):
        raise ValueError("Invalid sig length")

    sm = msg + sig

    # Set argument types: pointer to unsigned char, and length
    shared_lib.verify_signature.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t
    ]
    shared_lib.verify_signature.restype = ctypes.c_int

    msg_ctype = (ctypes.c_ubyte * len(msg)).from_buffer_copy(msg)
    sm_ctype  = (ctypes.c_ubyte * len(sm)).from_buffer_copy(sm)

    result = shared_lib.verify_signature(msg_ctype, sm_ctype, ctypes.c_size_t(len(sm_ctype)))
    return result


def calculate_oil(msg: bytes, sig:bytes) -> bytes:
    """
    Calculate expected oil with shared library.

    Args:
        msg (bytes): Message (256 bytes)
        sig (bytes): Signature (128 bytes)

    Returns:
        bytes: Expected oil
    """
    if (len(msg) != 256):
        raise ValueError("Invalid msg length")
    if (len(sig) != 128):
        raise ValueError("Invalid sig length")

    shared_lib.generate_faulted_sig.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),  # m
        ctypes.POINTER(ctypes.c_ubyte),  # sm
        ctypes.POINTER(ctypes.c_ubyte),  # salt (random if NULL)
        ctypes.POINTER(ctypes.c_ubyte),  # out
    ]
    shared_lib.generate_faulted_sig.restype = ctypes.c_int
    

    msg_ctype = (ctypes.c_ubyte * len(msg)).from_buffer_copy(msg) # use message from target
    sm_ctype = (ctypes.c_ubyte * (len(msg) + len(sig))).from_buffer_copy(msg + b'\x00' * len(sig)) # zeroed out signature
    salt_ctype = (ctypes.c_ubyte * 16).from_buffer_copy(sig[-16:]) # use salt from target signature
    sig_out = (ctypes.c_ubyte * len(sig))()
    
    shared_lib.generate_faulted_sig(msg_ctype, sm_ctype, salt_ctype, sig_out)
    oil_out = bytes(sig_out[:68+44])
    return bytes(oil_out)

