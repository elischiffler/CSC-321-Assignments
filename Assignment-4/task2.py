import bcrypt
import time
import re
import os
import nltk
from nltk.corpus import words
from multiprocessing import Pool, cpu_count

nltk.download('words', quiet=True)

def get_filtered_words():
    print("Preparing wordlist...")
    return list(set(w.lower() for w in words.words() if 6 <= len(w) <= 10))

def check_word_chunk(args):
    word_chunk, target_hash = args
    target_hash_bytes = target_hash.encode('utf-8')
    for word in word_chunk:
        if bcrypt.checkpw(word.encode('utf-8'), target_hash_bytes):
            return word
    return None

def parse_shadow_line(line):
    pattern = r"(\w+):(\$2b\$(\d+)\$[./0-9a-zA-Z]{53})"
    match = re.search(pattern, line)
    if match:
        return {
            "user": match.group(1),
            "full_hash": match.group(2),
            "workfactor": match.group(3)
        }
    return None

if __name__ == "__main__":
    shadow_file_path = "shadow.txt"
    wordlist = get_filtered_words()
    
    if not os.path.exists(shadow_file_path):
        print(f"Error: {shadow_file_path} not found in {os.getcwd()}")
    else:
        with open(shadow_file_path, "r") as f:
            lines = f.readlines()
            
        print(f"Found {len(lines)} lines in file. Starting crack...")

        for line in lines:
            parsed = parse_shadow_line(line)
            if not parsed:
                print(f"Skipping line (couldn't parse): {line.strip()[:30]}...")
                continue
                
            username = parsed['user']
            full_hash = parsed['full_hash']
            
            print(f"Checking {username} (WF: {parsed['workfactor']})...", end="", flush=True)
            
            start_time = time.time()
            num_cores = cpu_count()
            chunk_size = len(wordlist) // num_cores
            chunks = [(wordlist[i:i + chunk_size], full_hash) for i in range(0, len(wordlist), chunk_size)]
            
            with Pool(processes=num_cores) as pool:
                results = pool.map(check_word_chunk, chunks)
            
            found = False
            for res in results:
                if res:
                    print(f" MATCH! Password: {res} ({time.time()-start_time:.2f}s)")
                    found = True
                    break
            if not found:
                print(f" No match found in dictionary.")