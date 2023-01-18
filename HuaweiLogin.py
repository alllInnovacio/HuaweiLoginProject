# Codi per a entrar al sistema FucionSolar des de Python


import datetime
import json
import os
import requests
import urllib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA384, SHA1
from Crypto.Signature import pss
from Crypto import Random
import base64


#Funcions
def inicialitzaConexioHttp():
    # Creo la connexió que farem servir i les galetes.
    opener = requests.session() #Faré servir un objecte requests.session per a fer totes les consultes.
    opener.cookies.clear()
    return opener

def obteClauPublica(obridor):
    url = "https://eu5.fusionsolar.huawei.com/unisso/pubkey"
    resposta = obridor.get(url)
    print(resposta.text)
    dades = json.loads(resposta.text)
    print(dades)
    return [dades['version'],dades['pubKey'],dades['timeStamp'],dades['enableEncrypt']]

def preparaHexString(cadena):
    # Funció per a construir la frase en hexadecimal string com fa Huawei.
    hexString = ""
    for i in range(len(cadena)):
        hexString = hexString + format(cadena[i], '02X')
    #print(hexString)
    #print(len(hexString))
    return hexString

def hextob64_Huawei(cadena):
    #Funció que fa el mateix que la funció hextob64 de la web de Huawei
    b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    a=""
    for b in range(0,len(cadena),3):
        e = int(cadena[b:b+3],16)
        a = a + b64map[e>>6] + b64map[e&63]
    #print(a, len(a)&3)
    return a

def getSecureRandom_Huawei():
    #Funció que fa el mateix que la funció getSecureRandom de la web de Huawei
    arr = Random.get_random_bytes(16)
    cadena = ""
    for tros in arr:
        cadena = cadena + format(tros, '02X')
    return cadena

#Agafada d'internet
def quote_url(url, safe):
    """URL-encodes a string (either str (i.e. ASCII) or unicode);
    uses de-facto UTF-8 encoding to handle Unicode codepoints in given string.
    """
    return urllib.quote(unicode(url).encode('utf-8'), safe)

#Variables
usuari = "mch.enginyeria%40emelcat.cat"
contrasenya = "EMELCAT_ImpulsSolar"
fitxer_clau = "Clau_Prova.pem"

#frase = "7f807a6f9548c0dc2d65ec3d437500cb8b68dab7123e45468406ce9e0de5fbeefb474971b6fddaed82de2574f7de48bdf8e2303e287bd18406588694045d7e503cacbd14abbd7e3d659f5588cc2e58105cd4d7b581226b0a464cfbb8d1cd38c29829d915d63ed9372f66c2828181ae56a8083d7823dedf4bce311f6b5f1e229e178e5b1ed83c2dc26bc463957fc5cd715c89d10c0506e62bf88138af40e4708565e7da827996eb517598082b1e1437a6ffd91b591cd9370126e16e54078e580dd1530d61fe6527707b4bc69203ae8568b7f22e94df097ba63e15fc603271061ea92fc2fcfe248657308657aa36c0104801006b491756682bad717053b0cf4bab47065718306bf9889918f2b7016e3e0a182b24aa4cd852d4ad87cc32fd2c3cabdfd291c29f3c6c8c750a1f693b83bd6a172ddc0ac1324cce118ee4e09efd07051b9e6d261a892e7869e96505609e319ebdf6922c13f7ee5b6affac5a6e338d457f78287d54beee71fd758892c71c0d6819c84dae318bec1692b88201c8ad37c0"
#print(hextob64_Huawei(frase))
#exit(0)


#Recullo la clau pública de la web de Huawei
conexio = inicialitzaConexioHttp()

#Faig una primera crida per a inicialitzar les cookies
base_url_Huawei = 'eu5.fusionsolar.huawei.com/unisso/login.action?decision=1&service=https%3A%2F%2Fregion04eu5.fusionsolar.huawei.com%2Funisess%2Fv1%2Fauth%3Fservice%3D%252Fnetecowebext%252Fhome%252Findex.html%2523%252FLOGIN'
resposta = conexio.post(url="https://" + base_url_Huawei)
continguts = resposta.text
#print(continguts)

#Obtinc la clau pública
dadesClauPublica = obteClauPublica(conexio)
#print(dadesClauPublica)

#Creo els objectes RSA per a encriptar la contrasenya i fer la crida de login
#clauPublica= open(fitxer_clau,"r").read()
#print("Llegit:",clauPublica)
clauPublicaRSA = RSA.importKey(dadesClauPublica[1])
#clauPublicaRSA = RSA.importKey(clauPublica)
print(clauPublicaRSA)

aEncriptar = requests.utils.quote(contrasenya)
aEncriptarBytes = aEncriptar.encode("utf-8")
print(aEncriptarBytes)

#Creo el enxifrador per l'algortime RSAOAEP384 - RSA/ECB/OAEPWithSHA-384AndMGF1Padding
xifrador = PKCS1_OAEP.new(clauPublicaRSA, hashAlgo=SHA384, mgfunc=lambda x,y: pss.MGF1(x,y,SHA1))
enCriptat = xifrador.encrypt(aEncriptarBytes)

#Ho converteix a la sortida que donaria la llibreria KJUR de Javascript
hexString = preparaHexString(enCriptat)

#Faig la codificació que fa Huawei
aEnviar = hextob64_Huawei(hexString)
aEnviar = aEnviar + dadesClauPublica[0]

print("Contrasenya encriptada:\n",enCriptat)
print("Contrasenya a enviar:\n",aEnviar)

#exit(0)

urlLogin = "https://eu5.fusionsolar.huawei.com/unisso/v3/validateUser.action?service=%2Funisess%2Fv1%2Fauth%3Fservice%3D%252Fnetecowebext%252Fhome%252Findex.html&timeStamp=" + str(dadesClauPublica[2]) + "&nonce=" + getSecureRandom_Huawei() #7f102a533a8ec29f98856e18b1c6a9e"
print(urlLogin)
payload = {
        'organizationName': "",
        'password': aEnviar,
        'username': usuari
    }

capsalera = {
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Encoding': 'gzip, deflte, br',
    'Accept-Language': 'ca,en=US,;q=0.7,en;q=0.3',
    'Connection':'keep-alive',
    'Content-Lenght': '599',
    'Content-Type':'application/json',
    'DNT':'1',
    'Host':'eu5.fusionsolar.huawei.com',
    'Referer':'https://eu5.fusionsolar.huawei.com/unisso/login.action?decision=1&service=https%3A%2F%2Fregion04eu5.fusionsolar.huawei.com%2Funisess%2Fv1%2Fauth%3Fservice%3D%252Fnetecowebext%252Fhome%252Findex.html%2523%252FLOGIN',
    'Sec-Fetch-Dest':'empty',
    'Sec-Fetch-Mode':'cors',
    'Sec-Fetch-Site':'same-origin',
    'Sec-GPC':'1',
    'USer-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0',
    'X-Requested - With': 'XMLHttpRequest'
}

resposta = conexio.post(url=urlLogin, json=payload)#, headers=capsalera)
continguts = resposta.text
print(continguts)

