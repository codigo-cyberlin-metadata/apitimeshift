import falcon
from lib.middleware import AuthMiddleware
from lib.tokenValidate import getToken, ldapAuth
import json

class index(object):
    def on_get(self, req, resp):
        data = {'status': 200, 'author': 'giri@codigo.id', 'support':'infra@codigo.id'}
        resp.status = falcon.HTTP_200
        resp.body = json.dumps(data, sort_keys=True, indent=2, separators=(',', ': '))

    def on_post(self,req,resp):
        try:
            req.stream.read()
        except Exception as ex:
            raise falcon.HTTPError(falcon.HTTP_400,
                                   'Error',
                                   ex.message)
        try:
            data = {'title':'Notification','Description':'You Cant find something in here'}
            resp.status = falcon.HTTP_200
            resp.body = json.dumps(data, sort_keys=True, indent=2, separators=(',', ': '))
        except ValueError:
            raise falcon.HTTPError(falcon.HTTP_400,
                                   'Malformed JSON',
                                   'Could not decode the request body. The '
                                   'JSON was incorrect.')

route_check = AuthMiddleware(
    exempt_routes=['/getToken','/ldapAuth','/']
)
app = falcon.API(middleware=[route_check])
app.add_route('/', index())
app.add_route('/getToken', getToken())
app.add_route('/ldapAuth', ldapAuth())
