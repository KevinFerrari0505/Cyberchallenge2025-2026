import requests

r = requests.get("http://web-04.challs.olicyber.it/users", headers={"Accept":"application/xml"})
print(r.text)
