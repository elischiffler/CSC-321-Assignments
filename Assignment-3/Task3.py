import secrets
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import number

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

# ----------------- Task 3 Part 1: RSA Functions -----------------
def generate_rsa_keys(bits=2048):
    e = 65537
    #generate prime numbers
    p = number.getPrime(bits //2)
    q = number.getPrime(bits //2)

    n = p * q
    phi = (p-1) * (q-1)

    # Calculate d (modular inverse of e mod phi) 
    d = number.inverse(e, phi)

    return (n,e),(n,d)

def rsa_encrypt(message_int, public_key):
    n, e = public_key
    return pow(message_int, e, n)

def rsa_decrypt(ciphertext_int, private_key):
    n, d = private_key
    return pow(ciphertext_int, d, n)

def string_to_int(message_str):
    return int.from_bytes(message_str.encode(), 'big')

def int_to_string(message_int):
    # Calculate bytes needed: bit_length / 8
    length = (message_int.bit_length() + 7) // 8
    return message_int.to_bytes(length, 'big').decode()

if __name__ == "__main__":
    # ------------------------- Task 3 Part 1 -------------------------
    print("\n------------------- Task 3 Part 1: -------------------")

    #Generate Keys
    print("Generating RSA key pair (2048 bits)...")
    pub_key, priv_key = generate_rsa_keys(2048)
    n, e = pub_key
    print(f"n (modulus) length: {n.bit_length()} bits")
    print(f"e (exponent): {e}")

    #Test Encyption/Decryption----------------------------------------------
    original_msg = "Hello, World!"
    print(f"\nOriginal message: {original_msg}")

    m_int = string_to_int(original_msg)

    #Encrypt
    c_int = rsa_encrypt(m_int, pub_key)
    print(f"Encrypted (integer): {c_int}")

    #Decrypt
    decrypted_int = rsa_decrypt(c_int, priv_key)
    decrypted_msg = int_to_string(decrypted_int)
    print(f"Decrypted: {decrypted_msg}")

    #Test Encyption/Decryption2----------------------------------------------
    original_msg = "RSA Encryption"
    print(f"\nOriginal message: {original_msg}")

    m_int = string_to_int(original_msg)

    #Encrypt
    c_int = rsa_encrypt(m_int, pub_key)
    print(f"Encrypted (integer): {c_int}")

    #Decrypt
    decrypted_int = rsa_decrypt(c_int, priv_key)
    decrypted_msg = int_to_string(decrypted_int)
    print(f"Decrypted: {decrypted_msg}")

    #Test Encyption/Decryption3----------------------------------------------
    original_msg = "Cryptography is fun!"
    print(f"\nOriginal message: {original_msg}")

    m_int = string_to_int(original_msg)

    #Encrypt
    c_int = rsa_encrypt(m_int, pub_key)
    print(f"Encrypted (integer): {c_int}")

    #Decrypt
    decrypted_int = rsa_decrypt(c_int, priv_key)
    decrypted_msg = int_to_string(decrypted_int)
    print(f"Decrypted: {decrypted_msg}")

    #Test Encyption/Decryption4----------------------------------------------
    original_msg = "Test message for RSA"
    print(f"\nOriginal message: {original_msg}")

    m_int = string_to_int(original_msg)

    #Encrypt
    c_int = rsa_encrypt(m_int, pub_key)
    print(f"Encrypted (integer): {c_int}")

    #Decrypt
    decrypted_int = rsa_decrypt(c_int, priv_key)
    decrypted_msg = int_to_string(decrypted_int)
    print(f"Decrypted: {decrypted_msg}")


    if original_msg == decrypted_msg:
        print("\nSUCCESS: Message verified.")
    else:
        print("\nFAILURE: Decryption mismatch.")


    # ------------------------- Task 3 Part 2a -------------------------
    print("\n------------------- Task 3 Part 2a: -------------------")

    # Alice generates a symmetric key 's'
    s = secrets.randbits(128)
    print(f"Alice's original symmetric key (s): {s}")

    # Alice encyrpt key
    c = rsa_encrypt(s, pub_key)
    print(f"Encrypted symmetric key (c):\n{c}\n\n")


    # Mallory intercepts 'c' and modifies it
    # c' = c * (2^e) mod n
    c_prime = (c * pow(2, e, n)) % n
    print(f"Mallory's modified ciphertext (c'):\n{c_prime}\n\n")

    # Alternative Attack Approach
    print("Alternative malleability attack approach:\n")
    
    # Mallory chooses a specific s' and encrypts it directly
    # This simulates "Attack Method 2: Directly encrypt a chosen multiple of s"
    s_chosen = s * 2
    print(f"Mallory's chosen s': {s_chosen}\n")

    c_prime_alt = rsa_encrypt(s_chosen, pub_key)
    print(f"Mallory's computed c':\n{c_prime_alt}\n")

    # Verify Alice decrypts this to the chosen value
    alice_decrypted_val = rsa_decrypt(c_prime_alt, priv_key)
    print(f"Value Alice decrypts to: {alice_decrypted_val}\n")
    
    if alice_decrypted_val == s_chosen:
        print("Alternative attack successful: Alice decrypted to Mallory's chosen value!\n")

    s_prime = rsa_decrypt(c_prime, priv_key)
    print(f"Bob's decrypted value (s'): {s_prime}\n\n")
    
    # Mallory recovers 's' from s_prime
    # s = s_prime * 2^-1 mod n
    s_recovered = (s_prime * number.inverse(2, n)) % n
    print(f"Mallory's recovered symmetric key: {s_recovered}\n\n")
    
    if s == s_recovered:
        print("Attack successful: Mallory recovered the original symmetric key!\n\n")

    # AES Message Decryption Demo
    # Use s recovered to decrypt a message
    k_mallory = hashlib.sha256(int_to_bytes(s_recovered)).digest()[:16]
    k_bob = hashlib.sha256(int_to_bytes(s)).digest()[:16] # Simulating Bob/Alice key
    
    # Bob sends a message encrypted with his derived key
    msg = "Secret message from Bob to Alice"
    iv = secrets.token_bytes(16)
    c0 = aes_cbc_encrypt(k_bob, iv, msg)
    
    # Print ciphertext in hex (simulating "Bob's encrypted message (c0)")
    print(f"Bob's encrypted message (c0):\n{c0.hex()}\n")
    
    # Mallory decrypts it
    decrypted_text = aes_cbc_decrypt(k_mallory, iv, c0)
    print(f"Mallory's decrypted message: {decrypted_text}\n\n")

     # ------------------------- Task 3 Part 2b -------------------------
    print("\n------------------- Task 3 Part 2b: -------------------")

    print("Demonstrating RSA Signature Malleability\n")
    
    m1 = 12345
    m2 = 67890
    print(f"Original message 1 (m1): {m1}")
    print(f"Original message 2 (m2): {m2}\n")
    
    # Sign messages: s = m^d mod n
    s1 = pow(m1, priv_key[1], n)
    s2 = pow(m2, priv_key[1], n)
    print(f"Signature for m1:\n{s1}")
    print(f"Signature for m2:\n{s2}\n")

    #Verify signatures 
    print("Verifying original signatures:")
    print(f"Signature 1 is valid: {pow(s1, e, n) == m1}")
    print(f"Signature 2 is valid: {pow(s2, e, n) == m2}\n")

    # Forgery: m3 = m1*m2, s3 = s1*s2
    m3 = (m1 * m2) % n
    s3 = (s1 * s2) % n
    print(f"Mallory's new message (m3=m1*m2 mod n): {m3}")
    print(f"Mallory's forged signature for m3:\n{s3}\n")
    
    # Verify Forgery
    print("Verifying Mallory's forged signature:")
    is_valid_forgery = pow(s3, e, n) == m3
    print(f"Signature 3 is valid: {is_valid_forgery}\n")
    
    if is_valid_forgery:
        print("Attack successful: Mallory created a valid signature for a new message!")
