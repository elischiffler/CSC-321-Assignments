import secrets
import hashlib
from Crypto.Cipher import AES

# predifined q and g (IETF 1024-bit MODP group)
Q_HEX = """
B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
DF1FB2BC 2E4A4371
"""
q = int("".join(Q_HEX.split()), 16)
G_HEX = """
A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
855E6EEB 22B3B2E5
"""
g = int("".join(G_HEX.split()), 16)

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
    Ax = secrets.randbelow(q - 2) + 2
    Bx = secrets.randbelow(q - 2) + 2

    # compute public keys for A and B
    Ay = pow(g, Ax, q)
    By = pow(g, Bx, q)

    # compute shared keys for A and B
    As = pow(By, Ax, q)
    Bs = pow(Ay, Bx, q)

    # SHA256 s and truncate 16 bytes to get final shared key
    Ak = hashlib.sha256(int_to_bytes(As)).digest()[:16]
    Bk = hashlib.sha256(int_to_bytes(Bs)).digest()[:16]

    # ---------- print keys ----------
    print("\nAlice's Private Key (Ax):", Ax)
    print("\nAlice's Public Key (Ay):", Ay)
    
    print("\n\nBob's Private Key (Bx):", Bx)
    print("\nBob's Public Key (By):", By)

    print("\n\nAlice's Shared Key (As):", As)
    print("\nBob's Shared Key (Bs):", Bs)

    print("\n\nAlice's Final Shared Key (Ak):", Ak.hex())
    print("\nBob's Final Shared Key (Bk):", Bk.hex())

    # ------------ exchange messages ------------
    # verify that both shared keys are the same
    print("\nChecking if shared keys match...")
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
