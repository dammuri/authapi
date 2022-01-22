import requests

url = "http://127.0.0.1:5000/user"

payload = {
    "name":"danidamara",
    "passowrd":"vanadam11"
}
headers = {
  'x-access-token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwdWJsaWNfaWQiOiJlMDllMTVlMC1mYzg5LTQ0YzgtYjIxZi0wYTNkNTFjMWUxYzMiLCJleHAiOjE2NDI3NjExMjV9.1V0G3T2cjQTePLqEgdiRAnQ_G_sLRBuDHuAL7Y3LESU',
  'Authorization': 'Basic ZGFtbXVyaTp2YW5hZGFtMTE='
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)
