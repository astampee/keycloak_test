from flask import Flask, request
import json
import os
import jwt
import datetime
import sys
import re
from flask_oidc import OpenIDConnect
from oidc import create_client_secrets


app = Flask(__name__)
#print(os.environ, file=sys.stderr)
app_key = 'e852179e-4f11-42d6-b432-f37a2c9ca627'
create_client_secrets(realm='alchemybox')

#print(app_key, file=sys.stderr)
app.config.update({
    'SECRET_KEY': 'e852179e-4f11-42d6-b432-f37a2c9ca627',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_OPENID_REALM': 'alchemybox',  
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'#,
    #'OIDC_OPENID_REALM': 'http://localhost:5001/oidc_callback'
})

current_user = {"user_id": "bob_test", "admin":True}

oidc = OpenIDConnect(app)

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self,o)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if request.cookies.get('x-access-token'):
            token = request.cookies.get('x-access-token')

        if not token:
            return jsonify({'message':'Token is missing!'})
            #redirect to login

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = db.users.find_one({'user_id':data['user_id']})
        except:
            return jsonify({'message':'Token is invalid!'}), 401
            #redirect to login
        
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/', methods=['GET'])
def home():
    return '<h1>Alchemy box login test</h1><br />Avaliable routes:<ul><li><b>/hello</b> - Login test (protected route)</li><li><b>/logout</b> - logout user)</li></ul>'

@app.route("/tokens", methods=['GET'])
@oidc.accept_token()
def test_route():
    return json.dumps('Welcome %s' % g.oidc_token_info['sub'])

@app.route('/logout')
def logout():
    """Performs local logout by removing the session cookie."""

    oidc.logout()
    return 'Hi, you have been logged out! <a href="/">Return</a>'


@app.route('/hello', methods=['GET'])
@oidc.require_login
def hello_api():
    """OAuth 2.0 protected API endpoint accessible via AccessToken"""

    return json.dumps({'hello': 'Welcome %s' % g.oidc_token_info['sub']})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")