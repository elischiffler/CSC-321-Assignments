import secrets
import hashlib
from Crypto.Cipher import AES

# predifined q and g (IETF 1024-bit MODP group)
Q_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
FFFFFFFF FFFFFFFF
"""
q = int("".join(Q_HEX.split()), 16)
g = 2

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
    # ------------------------- Task 2 Part 1 -------------------------
    print("\n------------------- Task 2 Part 1 -------------------------")
    # generate random private keys for A and B
    Ax = secrets.randbelow(q - 2) + 2
    Bx = secrets.randbelow(q - 2) + 2

    # compute public keys for A and B
    Ay = pow(g, Ax, q)
    By = pow(g, Bx, q)

    print("\nAlice's Private Key (Ax):", Ax)
    print("\nAlice's Public Key (Ay):", Ay)
    
    print("\n\nBob's Private Key (Bx):", Bx)
    print("\nBob's Public Key (By):", By)

    # mallory intercepts and replaces Ay and By with q
    print("\n\n--- Mallory intercepts and replaces public keys with q ---")
    Ay = q
    By = q
    print("Modified Ay (sent to Bob):", Ay)
    print("\nModified By (sent to Alice):", By)

    # compute shared keys for A and B
    As = pow(By, Ax, q)
    Bs = pow(Ay, Bx, q)
    print("\n\nAlice's Shared Key (As):", As)
    print("\nBob's Shared Key (Bs):", Bs)

    # SHA256 s and truncate 16 bytes to get final shared key
    Ak = hashlib.sha256(int_to_bytes(As)).digest()[:16]
    Bk = hashlib.sha256(int_to_bytes(Bs)).digest()[:16]
    print("\n\nAlice's Derived Shared Key (Ak):", Ak.hex())
    print("\nBob's Derived Shared Key (Bk):", Bk.hex())

    # Mallory can also compute the shared key
    Ms = 0  # since Ay and By are q, shared secret s will be 0
    Mk = hashlib.sha256(int_to_bytes(Ms)).digest()[:16]
    print("\n\nMallory determines the shared secret:", Ms)
    print("\nMallory's derived Shared Key:", Mk.hex())

    # Check if all parties have the same shared key
    if Ak == Bk == Mk:
        print("\nAll shared keys match.")
    else:
        print("\nShared keys do not match.")

    # ------------ exchange messages ------------
    # Alice encrypts message to Bob
    Ak_iv = secrets.token_bytes(16)
    print("\nAlice's IV:", Ak_iv.hex())
    Ak_plaintext = "Hi Bob!"
    print("Alice's Message:", Ak_plaintext)
    c0 = aes_cbc_encrypt(Ak, Ak_iv, Ak_plaintext)
    print("Alice's Ciphertext:", c0.hex())
    
    # Mallory decrypts Alice's message
    print("\nMallory intercepts Alice's message...")
    Mk_plaintext = aes_cbc_decrypt(Mk, Ak_iv, c0)
    print("Mallory's Decrypted Message:", Mk_plaintext)

    # Bob receives and decrypts message from Alice
    print("\nBob receives Alice's message...")
    Bk_plaintext = aes_cbc_decrypt(Bk, Ak_iv, c0)
    print("Bob's Decrypted Message:", Bk_plaintext)

    # Bob encrypts message to Alice
    Bk_iv = secrets.token_bytes(16)
    print("\nBob's IV:", Bk_iv.hex())
    Bk_plaintext = "Hello Alice!"
    print("Bob's Message:", Bk_plaintext)
    c1 = aes_cbc_encrypt(Bk, Bk_iv, Bk_plaintext)
    print("Bob's Ciphertext:", c1.hex())

    # Mallory decrypts Bob's message
    print("\nMallory intercepts Bob's message...")
    Mk_plaintext = aes_cbc_decrypt(Mk, Bk_iv, c1)
    print("Mallory's Decrypted Message:", Mk_plaintext)

    # Alice receives and decrypts message from Bob
    print("\nAlice receives Bob's message...")
    Ak_plaintext = aes_cbc_decrypt(Ak, Bk_iv, c1)
    print("Alice's Decrypted Message:", Ak_plaintext)


    # ------------------------- Task 2 Part 2 -------------------------
    print("\n------------------- Task 2 Part 2 -------------------------")
    # alpha = 1 case
    print("MITM Generator Attack (alpha = 1)")
    g = 1
    print("Mallory sets g =", g)

    # generate random private keys for A and B
    Ax = secrets.randbelow(q - 2) + 2
    Bx = secrets.randbelow(q - 2) + 2

    # compute public keys for A and B
    Ay = pow(g, Ax, q)
    By = pow(g, Bx, q)
    print("\nAlice's Private Key (Ax):", Ax)
    print("\nAlice's Public Key (Ay):", Ay)
    print("\n\nBob's Private Key (Bx):", Bx)
    print("\nBob's Public Key (By):", By)

    # compute shared keys for A and B
    As = pow(By, Ax, q)
    Bs = pow(Ay, Bx, q)
    print("\n\nAlice's Shared Key (As):", As)
    print("\nBob's Shared Key (Bs):", Bs)
    # SHA256 s and truncate 16 bytes to get final shared key
    Ak = hashlib.sha256(int_to_bytes(As)).digest()[:16]
    Bk = hashlib.sha256(int_to_bytes(Bs)).digest()[:16]
    print("\n\nAlice's Derived Shared Key (Ak):", Ak.hex())
    print("\nBob's Derived Shared Key (Bk):", Bk.hex())

    print("\n\nMallory determines the shared secret: 1")
    Ms = 1
    Mk = hashlib.sha256(int_to_bytes(Ms)).digest()[:16]
    print("\nMallory's derived Shared Key:", Mk.hex())

    # Check if all parties have the same shared key
    if Ak == Bk == Mk:
        print("\nAll shared keys match.")
    else:
        print("\nShared keys do not match.")

    # Alice encrypts message to Bob
    Ak_plaintext = "Hi Bob!"
    print("Alice's Message:", Ak_plaintext)
    c0 = aes_cbc_encrypt(Ak, Ak_iv, Ak_plaintext)
    print("Alice's Ciphertext(c0):", c0.hex())

    # Bob encrypts message to Alice
    Bk_plaintext = "Hello Alice!"
    print("Bob's Message:", Bk_plaintext)
    c1 = aes_cbc_encrypt(Bk, Bk_iv, Bk_plaintext)
    print("Bob's Ciphertext(c1):", c1.hex())

    # Mallory decrypts both messages
    Mk_plaintext_0 = aes_cbc_decrypt(Mk, Ak_iv, c0)
    print("\nMallory's Decrypted Message from Alice:", Mk_plaintext_0)
    Mk_plaintext_1 = aes_cbc_decrypt(Mk, Bk_iv, c1)
    print("Mallory's Decrypted Message from Bob:", Mk_plaintext_1)

    # alpha = q case
    print("\n\nMITM Generator Attack (alpha = q)")
    g = q
    print("Mallory sets g =", g)
    # generate random private keys for A and B
    Ax = secrets.randbelow(q - 2) + 2
    Bx = secrets.randbelow(q - 2) + 2
    # compute public keys for A and B
    Ay = pow(g, Ax, q)
    By = pow(g, Bx, q)
    print("\nAlice's Private Key (Ax):", Ax)
    print("\nAlice's Public Key (Ay):", Ay)
    print("\n\nBob's Private Key (Bx):", Bx)
    print("\nBob's Public Key (By):", By)
    # compute shared keys for A and B
    As = pow(By, Ax, q)
    Bs = pow(Ay, Bx, q)
    print("\n\nAlice's Shared Key (As):", As)
    print("\nBob's Shared Key (Bs):", Bs)
    # SHA256 s and truncate 16 bytes to get final shared key
    Ak = hashlib.sha256(int_to_bytes(As)).digest()[:16]
    Bk = hashlib.sha256(int_to_bytes(Bs)).digest()[:16]
    print("\n\nAlice's Derived Shared Key (Ak):", Ak.hex())
    print("\nBob's Derived Shared Key (Bk):", Bk.hex())
    print("\n\nMallory determines the shared secret: 0")
    Ms = 0
    Mk = hashlib.sha256(int_to_bytes(Ms)).digest()[:16]
    print("\nMallory's derived Shared Key:", Mk.hex())
    # Check if all parties have the same shared key
    if Ak == Bk == Mk:
        print("\nAll shared keys match.")
    else:
        print("\nShared keys do not match.")
    # Alice encrypts message to Bob
    Ak_plaintext = "Hi Bob!"
    print("Alice's Message:", Ak_plaintext)
    c0 = aes_cbc_encrypt(Ak, Ak_iv, Ak_plaintext)
    print("Alice's Ciphertext(c0):", c0.hex())
    # Bob encrypts message to Alice
    Bk_plaintext = "Hello Alice!"
    print("Bob's Message:", Bk_plaintext)
    c1 = aes_cbc_encrypt(Bk, Bk_iv, Bk_plaintext)
    print("Bob's Ciphertext(c1):", c1.hex())
    # Mallory decrypts both messages
    Mk_plaintext_0 = aes_cbc_decrypt(Mk, Ak_iv, c0)
    print("\nMallory's Decrypted Message from Alice:", Mk_plaintext_0)
    Mk_plaintext_1 = aes_cbc_decrypt(Mk, Bk_iv, c1)
    print("Mallory's Decrypted Message from Bob:", Mk_plaintext_1)

    # alpha = q-1 case
    print("\n\nMITM Generator Attack (alpha = q-1)")
    g = q - 1
    print("Mallory sets g =", g)
    # generate random private keys for A and B
    Ax = secrets.randbelow(q - 2) + 2
    Bx = secrets.randbelow(q - 2) + 2
    # compute public keys for A and B
    Ay = pow(g, Ax, q)
    By = pow(g, Bx, q)
    print("\nAlice's Private Key (Ax):", Ax)
    print("\nAlice's Public Key (Ay):", Ay)
    print("\n\nBob's Private Key (Bx):", Bx)
    print("\nBob's Public Key (By):", By)
    # compute shared keys for A and B
    As = pow(By, Ax, q)
    Bs = pow(Ay, Bx, q)
    print("\n\nAlice's Shared Key (As):", As)
    print("\nBob's Shared Key (Bs):", Bs)
    # SHA256 s and truncate 16 bytes to get final shared key
    Ak = hashlib.sha256(int_to_bytes(As)).digest()[:16]
    Bk = hashlib.sha256(int_to_bytes(Bs)).digest()[:16]
    print("\n\nAlice's Derived Shared Key (Ak):", Ak.hex())
    print("\nBob's Derived Shared Key (Bk):", Bk.hex())
    # Mallory determines the shared secret based on parity of private keys
    if (Ay == 1) or (By == 1):
        Ms = 1
    else:
        Ms = q - 1
    Mk = hashlib.sha256(int_to_bytes(Ms)).digest()[:16]
    print("\n\nMallory determines the shared secret:", Ms)
    print("\nMallory's derived Shared Key:", Mk.hex())
    # Check if all parties have the same shared key
    if Ak == Bk == Mk:
        print("\nAll shared keys match.")
    else:
        print("\nShared keys do not match.")
    # Alice encrypts message to Bob
    Ak_plaintext = "Hi Bob!"
    print("Alice's Message:", Ak_plaintext)
    c0 = aes_cbc_encrypt(Ak, Ak_iv, Ak_plaintext)
    print("Alice's Ciphertext(c0):", c0.hex())
    # Bob encrypts message to Alice
    Bk_plaintext = "Hello Alice!"
    print("Bob's Message:", Bk_plaintext)
    c1 = aes_cbc_encrypt(Bk, Bk_iv, Bk_plaintext)
    print("Bob's Ciphertext(c1):", c1.hex())
    # Mallory decrypts both messages
    Mk_plaintext_0 = aes_cbc_decrypt(Mk, Ak_iv, c0)
    print("\nMallory's Decrypted Message from Alice:", Mk_plaintext_0)
    Mk_plaintext_1 = aes_cbc_decrypt(Mk, Bk_iv, c1)
    print("Mallory's Decrypted Message from Bob:", Mk_plaintext_1)