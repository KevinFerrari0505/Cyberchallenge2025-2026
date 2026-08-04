import requests

payload = {'username': 'admin', 'password': 'admin'}
r = requests.post('http://web-08.challs.olicyber.it/login', data=payload)
print(r.text)
