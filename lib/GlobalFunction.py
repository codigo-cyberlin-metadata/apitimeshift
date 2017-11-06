import uuid
import base64
from Crypto.Cipher import AES
import jwt
import urllib2
import json
import smtplib
import ldap
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def read_config(json_node,string):
    with open('config.json') as json_data:
        d = json.load(json_data)
        return d[json_node][string]

def sendmail(efrom,to,cc,subject,body,password):
    if cc is None:
        cece = read_config("email","milist")
    else:
        cc = cc.replace('[','').replace(']','').replace("'", "")
        if read_config("email","milist") in cc:
            cece = cc
        else:
            cece = cc + ','+read_config("email","milist")
    toaddr = ', '.join([to])
    msg = MIMEMultipart()
    msg['From'] = efrom
    msg['To'] = toaddr
    msg['Cc'] = cece
    msg['Subject'] = subject
    toaddrs = [toaddr]+cece.split(',')
    msg.attach(MIMEText(body, 'html'))
    try :
        server = smtplib.SMTP(read_config("email","smtp"), read_config("email","port"))
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(efrom, password)
        text = msg.as_string()
        server.sendmail(efrom, toaddrs, text)
        #server.set_debuglevel(True)
        server.quit()
        return 200
    except Exception as e:
        print e

def encryption(privateInfo):
    # 32 bytes = 256 bits
    # 16 = 128 bits
    # the block size for cipher obj, can be 16 24 or 32. 16 matches 128 bit.
    BLOCK_SIZE = 16
    # the character used for padding
    # used to ensure that your value is always a multiple of BLOCK_SIZE
    PADDING = '{'
    # function to pad the functions. Lambda
    # is used for abstraction of functions.
    # basically, its a function, and you define it, followed by the param
    # followed by a colon,
    # ex = lambda x: x+5
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    # encrypt with AES, encode with base64
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    # generate a randomized secret key with urandom
    secret = uuid.uuid4().hex
    # creates the cipher obj using the key
    cipher = AES.new(secret)
    # encodes you private info!
    encoded = EncodeAES(cipher, privateInfo)
    return encoded , secret

def decryption(encryptedString,secret):
	PADDING = '{'
	DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	#Key is FROM the printout of 'secret' in encryption
	#below is the encryption.
	encryption = encryptedString
	key = secret
	cipher = AES.new(key)
	decoded = DecodeAES(cipher, encryption)
	return decoded


def jwtDecode(token):
    payload = jwt.decode(token, read_config("jwt","secret"), algorithms=[read_config("jwt","algorithm")])
    return payload['username'], payload['password']

def sendTelegram(message):
    token = read_config("telegram","token")
    chatid = read_config("telegram","chatid")
    msg = 'Hai Sayang!! ' + message + ' dong!!'

    req = urllib2.Request("https://api.telegram.org/bot" + token + "/sendMessage?chat_id=" + chatid + "&text=" + msg)
    opener = urllib2.build_opener()
    f = opener.open(req)
    js = json.loads(f.read())
    result = json.dumps(dict(js), ensure_ascii=False)
    return result

def sendToRabbit(message):
    data = {"properties":{},"routing_key":"","payload":message,"payload_encoding":"string"}
    req = urllib2.Request(read_config("rabbit","url"))
    req.add_header("Authorization", read_config("rabbit","token"))
    req.add_header('Content-Type', 'application/json')
    response = urllib2.urlopen(req, json.dumps(data))
    return response

def ldap_auth(user):
    try:
        l = ldap.open(read_config("ldap","url"),read_config("ldap","port"))
        l.protocol_version = ldap.VERSION3
        username = read_config("ldap","bindDN")
        password = read_config("ldap","password")
        l.simple_bind(username, password)
    except ldap.LDAPError, e:
        print e
    
    baseDN = read_config("ldap","baseDN")
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = None
    searchFilter = "uid="+user
    try:
        ldap_result_id = l.search(baseDN, searchScope, searchFilter, retrieveAttributes)
        result_set = []
        while 1:
            result_type, result_data = l.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
        return result_set
    except ldap.LDAPError, e:
        return e

def userLDAP(user,password):
    userinfo = ldap_auth(user)
    cnuser = userinfo[0][0][0]
    l = ldap.initialize("ldap://"+read_config("ldap","url")+":"+str(read_config("ldap","port")))
    out = l.simple_bind_s(cnuser, password)
    return out[2]
