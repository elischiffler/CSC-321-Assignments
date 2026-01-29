import time
import random
import string
from Crypto.Hash import SHA256
import matplotlib.pyplot as plt

def hashInput(dataString):
    # initialize the SHA256 object
    hashObject = SHA256.new()
    if isinstance(dataString, str):
        hashObject.update(dataString.encode('utf-8'))
    else:
        hashObject.update(dataString)
    return hashObject.hexdigest()

def getTruncatedHash(dataString, bitCount):
    # Get the full hex digest
    fullHex = hashInput(dataString)
    # Convert hex to a large integer
    fullInt = int(fullHex, 16)
    # Shift right to keep only the top bitCount bits
    return fullInt >> (256 - bitCount)

def flipOneBit(inputBytes):
    # Convert string to bytearray
    ba = bytearray(inputBytes.encode('utf-8'))
    # Flip the very last bit of the first byte
    ba[0] = ba[0] ^ 1
    return ba

def findBirthdayCollision(bitCount):
    seenHashes = {}
    attempts = 0
    startTime = time.time()

    while True:
        attempts += 1
        # Generate a random string to hash
        randomStr = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        truncatedHash = getTruncatedHash(randomStr, bitCount)
        
        if truncatedHash in seenHashes:
            # Collision found
            endTime = time.time()
            totalTime = endTime - startTime
            return randomStr, seenHashes[truncatedHash], attempts, totalTime
        
        seenHashes[truncatedHash] = randomStr

def printHashedInput(userInput):
    result = hashInput(userInput)
    print(f"User Input: {userInput}")
    print(f"SHA-256: {result}")
    print("")

def printHamming(orignialString):
    modifiedBytes = flipOneBit(orignialString)
    modifiedString = modifiedBytes.decode('utf-8', errors='ignore')
    
    hash1 = hashInput(orignialString)
    hash2 = hashInput(modifiedBytes)

    
    print(f"Original String: '{orignialString}'")
    print(f"Modified String: '{modifiedString}'") 
    print(f"Hash 1: {hash1}")
    print(f"Hash 2: {hash2}")
    print("")

# Example usage
print("---------------- Task 1a: SHA-256 Hashing ----------------\n")
printHashedInput("Hello, World!")
printHashedInput("hello, World!")
printHashedInput("This is an example string to hash.")

# ---------------- Task 1b: Hamming Distance ----------------
print("---------------- Task 1b: 1-Bit Hamming Distance ----------------\n")

printHamming("apple")
printHamming("cryptography")
printHamming("00000000")

# ---------------- Task 1c: Collision Testing ----------------
print("---------------- Task 1c: Finding Collisions (Birthday Attack) ----------------\n")
print(f"{'Bits'} | {'Inputs':<10} | {'Time (s)':<12} | {'Collision Pair'}")
print("-" * 70)

results = []

# Testing from 8 bits to 50 bits in increments of 2
for bits in range(8, 51, 2): 
    m1, m2, inputs, duration = findBirthdayCollision(bits)
    results.append((bits, inputs, duration))
    print(f"{bits:<4} | {inputs:<10} | {duration:<12.5f} | '{m1}' == '{m2}'")

# Graph 1: Digest Size vs Collision Time
plt.figure(figsize=(10, 5))
plt.plot([r[0] for r in results], [r[2] for r in results], marker='o', color='b')
plt.title('Digest Size vs Collision Time')
plt.xlabel('Digest Size (Bits)')
plt.ylabel('Time (Seconds)')
plt.grid(True)
plt.savefig('collision_time_graph.png')

# Graph 2: Digest Size vs Number of Inputs
plt.figure(figsize=(10, 5))
plt.plot([r[0] for r in results], [r[1] for r in results], marker='s', color='r')
plt.title('Digest Size vs Number of Inputs')
plt.xlabel('Digest Size (Bits)')
plt.ylabel('Number of Inputs')
plt.grid(True)
plt.savefig('collision_inputs_graph.png')