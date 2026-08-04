import requests

s = requests.Session()

url = 'http://web-11.challs.olicyber.it/login'
url2 = 'http://web-11.challs.olicyber.it/flag_piece'

payload = {'username': 'admin', 'password': 'admin'}

# login
r = s.post(url, json=payload)
csrf = r.json()["csrf"]

flag = ""

for i in range(4):
    params = {
        "index": i,
        "csrf": csrf
    }

    r = s.get(url2, params=params)

    print(r.text)  # debug

    res = r.json()

    flag += res["flag_piece"]
    csrf = res["csrf"]

print(flag)
