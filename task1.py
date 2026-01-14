"""
Console commands to run:
  python task1.py ecb cp.bmp cp_ecb.bmp
  python task1.py cbc cp.bmp cp_cbc.bmp
  python task1.py ecb mustang.bmp mustang_ecb.bmp
  python task1.py cbc mustang.bmp mustang_cbc.bmp
"""
import argparse
import secrets

from Crypto.Cipher import AES

BLOCK_SIZE = 16  # AES block size in bytes (128 bits)

# PKCS#7 pad to a multiple of block_size
def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

# XOR two equal-length byte strings
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# encrypt exactly one 16-byte block
def aes128_encrypt_block(key: bytes, block16: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block16)

# ECB over our full blocks
def ecb_encrypt(key: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        out.extend(aes128_encrypt_block(key, data[i : i + BLOCK_SIZE]))
    return bytes(out)

# CBC over our full blocks
def cbc_encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    out = bytearray()
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        x = xor_bytes(block, prev)
        c = aes128_encrypt_block(key, x)
        out.extend(c)
        prev = c
    return bytes(out)

# Return the pixel array offset from a BMP file header
def bmp_pixel_offset(bmp: bytes) -> int:
    return int.from_bytes(bmp[10:14], byteorder="little", signed=False)


def main() -> int:
    # parse our console arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("ecb", "cbc"))
    parser.add_argument("infile")
    parser.add_argument("outfile")
    args = parser.parse_args()

    # read our input file and generate a random key
    with open(args.infile, "rb") as f:
        plaintext = f.read()
    key = secrets.token_bytes(16)

    # calculate where pixel data starts
    offset = bmp_pixel_offset(plaintext)

    # separate our header and pixels
    header = plaintext[:offset]
    pixels = plaintext[offset:]
    padded_pixels = pkcs7_pad(pixels, BLOCK_SIZE)

    iv: bytes | None
    if args.mode == "ecb":
        # ECB mode
        iv = None
        enc_pixels = ecb_encrypt(key, padded_pixels)
    else:
        # CBC mode
        iv = secrets.token_bytes(16)
        enc_pixels = cbc_encrypt(key, padded_pixels, iv)

    # add header back to ciphertext
    ciphertext = header + enc_pixels

    # write out our encrypted file and metadata
    with open(args.outfile, "wb") as f:
        f.write(ciphertext)

    # exit
    return 0


if __name__ == "__main__":
    raise SystemExit(main())