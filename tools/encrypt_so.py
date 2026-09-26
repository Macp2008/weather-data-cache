#!/usr/bin/env python3
"""Cifra un archivo .so usando AES-256-GCM via libcrypto (ctypes)."""
import sys
import os
import ctypes
import ctypes.util
from pathlib import Path

def load_libcrypto():
    lib_path = ctypes.util.find_library("crypto")
    if not lib_path:
        for candidate in [
            "libcrypto.so", "libcrypto.so.3", "libcrypto.so.1.1",
            "/data/data/com.termux/files/usr/lib/libcrypto.so",
            "/system/lib64/libcrypto.so",
        ]:
            if os.path.exists(candidate):
                lib_path = candidate
                break
    if not lib_path:
        print("[!] libcrypto no encontrada", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Usando libcrypto: {lib_path}")
    lib = ctypes.CDLL(lib_path)

    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_new.argtypes = []

    lib.EVP_CIPHER_CTX_free.restype = None
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

    lib.EVP_aes_256_gcm.restype = ctypes.c_void_p
    lib.EVP_aes_256_gcm.argtypes = []

    lib.EVP_EncryptInit_ex.restype = ctypes.c_int
    lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    lib.EVP_EncryptUpdate.restype = ctypes.c_int
    lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]

    lib.EVP_EncryptFinal_ex.restype = ctypes.c_int
    lib.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]

    lib.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]

    lib.ERR_error_string_n.restype = None
    lib.ERR_error_string_n.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t]

    lib.ERR_get_error.restype = ctypes.c_ulong
    lib.ERR_get_error.argtypes = []

    return lib

def get_error(lib):
    buf = ctypes.create_string_buffer(256)
    lib.ERR_error_string_n(lib.ERR_get_error(), buf, 256)
    return buf.value.decode(errors="ignore")

def encrypt_file(input_path, output_path, key_hex, lib):
    key = bytes.fromhex(key_hex)
    if len(key) != 32:
        print(f"[!] Llave debe ser 32 bytes. Tiene {len(key)}.", file=sys.stderr)
        sys.exit(1)

    iv = os.urandom(12)
    plaintext = Path(input_path).read_bytes()

    # Buffer de salida con espacio extra para el tag
    outbuf = ctypes.create_string_buffer(len(plaintext) + 32)
    tag = ctypes.create_string_buffer(16)
    outl = ctypes.c_int(0)
    final_outl = ctypes.c_int(0)

    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        print(f"[!] EVP_CIPHER_CTX_new falló: {get_error(lib)}", file=sys.stderr)
        sys.exit(1)

    try:
        # 1. Inicializar contexto con cipher
        rc = lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, None, None)
        if rc != 1:
            print(f"[!] Init cipher: {get_error(lib)}", file=sys.stderr)
            sys.exit(1)

        # 2. Set IV length = 12 bytes
        rc = lib.EVP_CIPHER_CTX_ctrl(ctx, 0x09, 12, None)
        if rc != 1:
            print(f"[!] SET_IVLEN: {get_error(lib)}", file=sys.stderr)
            sys.exit(1)

        # 3. Set key + IV
        rc = lib.EVP_EncryptInit_ex(ctx, None, None, key, iv)
        if rc != 1:
            print(f"[!] Init key/iv: {get_error(lib)}", file=sys.stderr)
            sys.exit(1)

        # 4. Encrypt update
        rc = lib.EVP_EncryptUpdate(ctx, outbuf, ctypes.byref(outl), plaintext, len(plaintext))
        if rc != 1:
            print(f"[!] EncryptUpdate: {get_error(lib)}", file=sys.stderr)
            sys.exit(1)

        update_len = outl.value

        # 5. Encrypt final
        rc = lib.EVP_EncryptFinal_ex(
            ctx,
            ctypes.cast(ctypes.addressof(outbuf) + update_len, ctypes.c_char_p),
            ctypes.byref(final_outl)
        )
        if rc != 1:
            print(f"[!] EncryptFinal: {get_error(lib)}", file=sys.stderr)
            sys.exit(1)

        total_cipher = update_len + final_outl.value

        # 6. Get GCM tag
        rc = lib.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, tag)
        if rc != 1:
            print(f"[!] GET_TAG: {get_error(lib)}", file=sys.stderr)
            sys.exit(1)

        # 7. Construir archivo final: [IV][ciphertext][tag]
        final_data = iv + outbuf.raw[:total_cipher] + tag.raw
        Path(output_path).write_bytes(final_data)

        print(f"[OK] {input_path} -> {output_path}")
        print(f"     IV:    {len(iv)} bytes")
        print(f"     Data:  {total_cipher} bytes (ciphertext)")
        print(f"     Tag:   16 bytes")
        print(f"     Total: {len(final_data)} bytes")

    finally:
        lib.EVP_CIPHER_CTX_free(ctx)

if __name__ == "__main__":
    lib = load_libcrypto()
    if len(sys.argv) != 4:
        print("Uso: encrypt_so.py <input> <output> <key_hex>", file=sys.stderr)
        sys.exit(1)
    encrypt_file(sys.argv[1], sys.argv[2], sys.argv[3], lib)
