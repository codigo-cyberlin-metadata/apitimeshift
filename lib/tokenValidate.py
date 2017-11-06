from lib.GlobalFunction import encryption, read_config, userLDAP
from datetime import datetime, timedelta
import falcon
import jwt
import json

class getToken(object):
    def on_post(self,req, resp):
        try:
            rawjson = req.stream.read()
            data = json.loads(rawjson, encoding='utf-8')
            username = data['username']
            password = data['password']
            enco , secre = encryption(password)
            payload = {
                'username': username,
                'password': enco,
                'exp': datetime.utcnow() + timedelta(seconds=read_config("jwt","exp"))
            }
            jwt_token = jwt.encode(payload, read_config("jwt","secret"), read_config("jwt","algorithm"))
            data = {"token": jwt_token.decode('utf-8')}
            resp.status = falcon.HTTP_200
            resp.body = json.dumps(data, sort_keys=True, indent=2, separators=(',', ': '))

        except Exception as ex:
            raise falcon.HTTPError(falcon.HTTP_400,
                                   'Error',
                                   ex.message)
        
class ldapAuth(object):
    def on_post(self,req, resp):
        try:
            rawjson = req.stream.read()
            data = json.loads(rawjson, encoding='utf-8')
            username = data['username']
            password = data['password']
            if userLDAP(username,password) == 1:
                data = {"login": True}
                resp.status = falcon.HTTP_200
                resp.body = json.dumps(data, sort_keys=True, indent=2, separators=(',', ': '))
            else:
                data = {"login": False}
                resp.status = falcon.HTTP_200
                resp.body = json.dumps(data, sort_keys=True, indent=2, separators=(',', ': '))
        except Exception as ex:
            raise falcon.HTTPError(falcon.HTTP_400,
                                   'Error',
                                   ex.message)
