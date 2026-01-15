from __future__ import annotations

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16

# Generate random AES key and IV
KEY = get_random_bytes(16)
IV = get_random_bytes(16)

# pkcs7 padding function
def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

# pkcs7 unpadding function
def pkcs7_unpad(padded: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = padded[-1]
    return padded[:-pad_len]

# URL-encoding function
def url_encode_user_data(userdata: str) -> str:
    return userdata.replace(";", "%3B").replace("=", "%3D")

# submit funtion
def submit(userdata: str) -> bytes:
    # construct plaintext strings
    prefix = "userid=456;userdata="
    suffix = ";session-id=31337"
    safe_userdata = url_encode_user_data(userdata)

    # combine all parts
    full = (prefix + safe_userdata + suffix).encode("utf-8")

    # add our padding
    padded = pkcs7_pad(full, BLOCK_SIZE)

    # encrypt with AES-CBC and return ciphertext
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(padded)

# verify function
def verify(ciphertext: bytes) -> bool:
    # decrypt with AES-CBC
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext_padded = cipher.decrypt(ciphertext)

    # remove padding
    plaintext = pkcs7_unpad(plaintext_padded, BLOCK_SIZE)

    # check for presence of ";admin=true;" in plaintext
    return b";admin=true;" in plaintext

# function to perform CBC bit-flipping attack
def cbc_bitflip_attack() -> tuple[bytes, bytes, bytes]:
    # create a placeholder block that we will modify
    placeholder_block = b"AadminAtrueA"

    prefix = b"userid=456;userdata="
    prefix_len = len(prefix)  # used only for alignment

    # Add filler bytes so that our placeholder block starts exactly at the
    # beginning of a new AES block. This makes the bit-flipping predictable.
    filler_len = (-prefix_len) % BLOCK_SIZE
    filler = b"B" * filler_len

    userdata = (filler + placeholder_block).decode("ascii")
    original_ciphertext = submit(userdata)

    # At this point, the placeholder block is block-aligned in the plaintext,
    # so we can figure out which ciphertext block to modify.
    start_offset = prefix_len + filler_len
    target_block_index = start_offset // BLOCK_SIZE  # 0-based block index in plaintext

    modified = bytearray(original_ciphertext)
    prev_block_start = (target_block_index - 1) * BLOCK_SIZE

    # Flip specific bytes in the previous ciphertext block so that
    # 'AadminAtrueA' decrypts into ';admin=true;'.
    flips = {
        0: ord("A") ^ ord(";"),
        6: ord("A") ^ ord("="),
        11: ord("A") ^ ord(";"),
    }
    for pos_in_block, delta in flips.items():
        modified[prev_block_start + pos_in_block] ^= delta

    modified_ciphertext = bytes(modified)

    # Decrypt the modified ciphertext so we can see the resulting plaintext
    # and verify that the attack worked.
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    pt_padded = cipher.decrypt(modified_ciphertext)
    modified_plaintext = pkcs7_unpad(pt_padded, BLOCK_SIZE)

    return original_ciphertext, modified_ciphertext, modified_plaintext

# turn bytes to hex string
def _hex(b: bytes) -> str:
    return b.hex()


if __name__ == "__main__":
    # verify() is false on honest ciphertext
    user_input = "You’re the man now, dog"
    ciphertext = submit(user_input)
    print("Verify (honest ciphertext):", verify(ciphertext))

    # Perform CBC bit-flipping attack
    original_ciphertext, modified_ciphertext, modified_plaintext = cbc_bitflip_attack()

    print("\n--- CBC bit-flipping attack ---")
    print("Original ciphertext (hex):")
    print(_hex(original_ciphertext))
    print("\nModified ciphertext (hex):")
    print(_hex(modified_ciphertext))

    print("\nVerify (modified ciphertext):", verify(modified_ciphertext))
    print("\nDecrypted plaintext after attack (utf-8, errors replaced):")
    print(modified_plaintext.decode("utf-8", errors="replace"))