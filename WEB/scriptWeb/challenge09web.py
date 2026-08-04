import requests
import json

payload = {'username': 'admin', 'password': 'admin'}
url = 'http://web-09.challs.olicyber.it/login'
r = requests.post(url, json = payload)
print(r.text)
