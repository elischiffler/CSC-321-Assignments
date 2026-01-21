import secrets
import hashlib
from Crypto.Cipher import AES

# predifined q and g
q = 37
g = 5

# PKCS#7 padding
def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    padding = bytes([pad_len] * pad_len)
    return data + padding

# PKCS#7 unpadding
def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

# CBC encryption
def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: str) -> bytes:
    plaintext = plaintext.encode()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pkcs7_pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

# CBC decryption
def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = pkcs7_unpad(padded_plaintext)
    return plaintext.decode()

# function to convert integer to bytes
def int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")

if __name__ == "__main__":
    # generate random private keys for A and B
    Ax = secrets.randbelow(35) + 1
    Bx = secrets.randbelow(35) + 1 

    # compute public keys for A and B
    Ay = pow(g, Ax, q)
    By = pow(g, Bx, q)

    # compute shared keys for A and B
    As = pow(By, Ax, q)
    Bs = pow(Ay, Bx, q)

    # SHA256 s and truncate 16 bytes to get final shared key
    Ak = hashlib.sha256(int_to_bytes(As)).digest()[:16]
    Bk = hashlib.sha256(int_to_bytes(Bs)).digest()[:16]


    # ------------ exchange messages ------------
    # verify that both shared keys are the same
    print("Checking if shared keys match...")
    if Ak == Bk:
        print("Shared keys match.")
    else:
        print("Shared keys do not match.")

    # Alice encrypts message to Bob
    Ak_iv = secrets.token_bytes(16)
    print("\nAlice's IV:", Ak_iv.hex())
    Ak_plaintext = "Hi Bob!"
    print("Alice's Message:", Ak_plaintext)
    Ak_ciphertext = aes_cbc_encrypt(Ak, Ak_iv, Ak_plaintext)
    print("Alice's Ciphertext:", Ak_ciphertext.hex())

    # Bob receives and decrypts message from Alice
    print("\nBob receives Alice's message...")
    Bk_plaintext = aes_cbc_decrypt(Bk, Ak_iv, Ak_ciphertext)
    print("Bob's Decrypted Message:", Bk_plaintext)

    # Bob encrypts message to Alice
    Bk_iv = secrets.token_bytes(16)
    print("\nBob's IV:", Bk_iv.hex())
    Bk_plaintext = "Hello Alice!"
    print("Bob's Message:", Bk_plaintext)
    Bk_ciphertext = aes_cbc_encrypt(Bk, Bk_iv, Bk_plaintext)
    print("Bob's Ciphertext:", Bk_ciphertext.hex())

    # Alice receives and decrypts message from Bob
    print("\nAlice receives Bob's message...")
    Ak_plaintext = aes_cbc_decrypt(Ak, Bk_iv, Bk_ciphertext)
    print("Alice's Decrypted Message:", Ak_plaintext)