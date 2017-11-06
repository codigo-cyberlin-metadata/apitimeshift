import falcon
import jwt
from lib.GlobalFunction import read_config
class AuthMiddleware(object):

    def __init__(self, exempt_routes=None):
        self.exempt_routes = exempt_routes or []
       
    def process_resource(self, req, resp, resource, params):
        if req.path in self.exempt_routes:
            if req.path is '/':
                return
            basic_token = req.get_header('Authorization')
            if basic_token is None:
                description = ('Please Add Header Token and try again')
                raise falcon.HTTPUnauthorized('Auth token required', description)
            if basic_token in read_config("middleware","basic_auth"):
                return
            else:
                description = ('Your token is wrong!')
                raise falcon.HTTPUnauthorized('Token Error!', description)
            
        token = req.get_header('Authorization')
        if token is None:
            description = ('Please Add Header Token and try again')
            raise falcon.HTTPUnauthorized('Auth token required',description)
        try:
            print "ok"
        except (jwt.DecodeError, jwt.ExpiredSignatureError):
            description = ('The provided auth token is not valid. '
                           'Please request a new token and try again.')
            raise falcon.HTTPUnauthorized('Authentication required',
                                      description)
