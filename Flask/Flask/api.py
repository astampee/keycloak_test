#Add logout and romve cookie
#Validate token
#Set SSL
#encrypt cookie
#give cookie expiry



from flask import Flask, request, jsonify, render_template, make_response, redirect, url_for
import os
import sys
from keycloak import KeycloakOpenID
from functools import wraps
from oic.oic.message import AuthorizationResponse
from oic.oic import Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic import rndstr
from werkzeug.urls import iri_to_uri
from flask_cors import CORS, cross_origin
import jwt
import datetime

app = Flask(__name__)
CORS(app)



# Configure client
keycloak_openid = KeycloakOpenID(server_url="http://keycloak:8080/auth/", client_id="alchemybox", realm_name="alchemybox", client_secret_key="e852179e-4f11-42d6-b432-f37a2c9ca627")
client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
provider_info = client.provider_config('http://keycloak:8080/auth/realms/alchemybox')

def get_token(url, provider_info, client):
    print(url, file=sys.stderr)
    ia_tkn = "eyJhbGciOiJSUzI1NiIsImtpZCIgOiAiWnc0VTNtVV9oZVhUWjdMc2hGcUJyX1YzOHcxbXgyV2h5d3ZCYU9DZzFFayJ9.eyJqdGkiOiIzMTQzYTZiMC0wYjI5LTRkODMtYWMzZC0zMWQ1MTk5MDE2YWQiLCJleHAiOjAsIm5iZiI6MCwiaWF0IjoxNTQ0MDIyMTYxLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvYXV0aC9yZWFsbXMvYWxjaGVteWJveCIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9hdXRoL3JlYWxtcy9hbGNoZW15Ym94IiwidHlwIjoiSW5pdGlhbEFjY2Vzc1Rva2VuIn0.BWPrdFMj1Rm_PoB7rx_C8XFfCJ3cF1JmdAIZqsuiB9g7OxgBPr6AfRlq01IQb6fu2fQ95hXO_Vcp7BzLHjm9V8coKEyRnhMvZQGCt4KAmtVaxjIZooL-XHsq-oAZEgrCktwNcQyHyCjQSoQ-4v-fYjurFf0KI5_ycRnDQo4VEJnL2QijOtszWkqa4aqiemO9_L_AM5-BzKTFivpa2SVZC4dyH_YfVi4EduRHCZGyjjQpjoIVc7fgOVdG247z3Z1LTi_Tot--4J_e_f0R1XjW8Zb76tjU-fpXNQL_wjcA_NZNHs-dY-9p7Ol2ZbjS6humnto7h5tkWn7w3GXEL78kZA"
    
    print(provider_info)
    args = {
    "redirect_uris": ['http://localhost:5010/oidc']
    }
    try:
        registration_response = client.register(provider_info["registration_endpoint"], registration_token=ia_tkn,  **args)
        print(registration_response)
    except Exception as e:
        print(e, file=sys.stderr)
    aresp = client.parse_response(AuthorizationResponse, info=url,sformat="urlencoded")
    print(aresp, file=sys.stderr)
    args = {
    "code": aresp["code"]
    }
    try:
        resp = client.do_access_token_request(state=aresp["session_state"],
                                            request_args=args,
                                            authn_method="client_secret_basic")
        
        print(resp, file=sys.stderr)
        return resp
    except Exception as e:
        print(e, file=sys.stderr)
        return e

    

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        #prob should encrypt cookie and set expiration
        [print(x, file=sys.stderr) for x in request.cookies]
        if request.cookies.get('x-access-token'):
            token = request.cookies.get('x-access-token')
            decoded = jwt.decode(token, verify=False)
            exp = datetime.datetime.utcfromtimestamp(int(decoded['exp']))
            print(exp, file=sys.stderr)
            #expiry not working
            '''if exp > datetime.datetime.now():
                print('Token expired', file=sys.stderr)
                return redirect('/login{}'.format(request.path))
            else:'''
            current_user = {'user_id':decoded['preferred_username'], 'first_name':decoded['given_name'], 'surname':decoded['family_name'], 'email':decoded['email'], 'name':decoded['name']}
            print(current_user, file=sys.stderr)
        if not token:
            #return jsonify({'message':'Token is missing!'})
            #redirect to login
            print('No token found', file=sys.stderr)
            return redirect('/login{}'.format(request.path))

        del decoded
        del token
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/', methods=['GET'])
def home():
    return '<h1>Alchemy box login test</h1><br />Avaliable routes:<ul><li><b><a href="/hello">/hello</a></b> - Login test (protected route)</li><li><b><a href="/logout">/logout</a></b> - logout user</li><li><b><a href="/login">/login</a></b> - login user</li></ul>'

@app.route("/<user>/<password>", methods=['GET'])
def login_test(user, password):
    try:
        try:
            tkn = request.cookies.get('x-access-token')
            userinfo = keycloak_openid.userinfo(tkn)
            return '<h1>{} you are already logged in</h1><br /><a href="/logout">Logout</a>'.format(userinfo['given_name'])
        except:
            resp = make_response(redirect("/login"))
        
        try:
            #print(user + ' ' + password)
            t = keycloak_openid.token(str(user),str(password))
        except Exception as e:
            #return 'Invalid username or password'
            return str(e)
        
        resp.set_cookie('x-access-token', t['access_token'].encode('utf-8'))
        resp.set_cookie('x-refresh-token', t['refresh_token'].encode('utf-8'))
        return resp
    except Exception as e:
        print(e)
        return 'Could not save cookie'


@app.route("/keycloak", methods=['GET', 'POST'])
def keycloak():
    if request.method == "GET":
        try:
            tkn = request.cookies.get('x-access-token')
            userinfo = keycloak_openid.userinfo(tkn)
            #return render_template("login.html", msg="{} you are already logged in".format(userinfo['given_name']))
            #return '<h1>{} you are already logged in</h1><br /><a href="/logout">Logout</a>'.format(userinfo['given_name'])
            return redirect("/hello")
        except:
            #resp = make_response(redirect("/login"))
            return redirect("http://localhost:8080/auth/realms/alchemybox/protocol/openid-connect/auth?client_id=alchemybox&response_mode=fragment&response_type=code&login=true&redirect_uri=http://localhost:5010/oidc")
    
    if request.method == "POST":
        try:            
            try:
                print(request.form)
                user = request.form['user']
                password = request.form['password']
                t = keycloak_openid.token(str(user),str(password))
            except Exception as e:
                return render_template("login.html", msg=e)
            resp = make_response(redirect("/hello"))
            resp.set_cookie('x-access-token', t['access_token'].encode('utf-8'))
            resp.set_cookie('x-refresh-token', t['refresh_token'].encode('utf-8'))
            return resp
        except Exception as e:
            print(e)
            return render_template("login.html", msg="Could not save cookie")
    

@app.route("/oidc", methods=['GET', 'POST'])
def oidc_callback():
    if request.method == 'GET':
        return render_template("callback.html")
    
    if request.method == 'POST':
        '''output = ""
        try:
            for i, key in enumerate(request.args):
                if i == 0:
                    output += "<h2>Request Parameters</h2>"
                output += "<p><b>{}</b> : {}</p>".format(key, request.args[key])
        except:
            pass

        try:
            for i, key in enumerate(request.json):
                if i == 0:
                    output += "<br />"
                    output += "<h2>Request JSON</h2>"
                output += "<p><b>{}</b> : {}</p>".format(key, request.json[key])
        except:
            pass

        try:
            for i, key in enumerate(request.form):
                if i == 0:
                    output += "<br />"
                    output += "<h2>Request Form</h2>"
                output += "<p><b>{}</b> : {}</p>".format(key, request.form[key])
        except:
            pass


        try:
            for i, key in enumerate(request.data):
                if i == 0:
                    output += "<br />"
                    output += "<h2>Request Data</h2>"
                output += "<p><b>{}</b> : {}</p>".format(key, request.data[key])
        except:
            pass'''
        #print(request.form['fragment'], file=sys.stderr)
        #return output
        tkn = get_token(request.form['fragment'], provider_info, client)
        return request.form['fragment']
        #print(request.data['fragment'])
        #print(tkn)
        #return tkn
    

@app.route("/login/<redirect>", methods=['GET', 'POST'])
@cross_origin()
def login(redirect):
    return render_template('login.html', redirect=redirect)

@app.route("/callback", methods=['GET', 'POST'])
def callback():
    output = ""
    tkn = request.cookies.get('oidc_id_token')
    output += str(tkn)
    
    try:
        for i, key in enumerate(request.args):
            if i == 0:
                output += "<h2>Request Parameters</h2>"
            output += "<p><b>{}</b> : {}</p>".format(key, request.args[key])
    except:
        pass

    try:
        for i, key in enumerate(request.json):
            if i == 0:
                output += "<br />"
                output += "<h2>Request JSON</h2>"
            output += "<p><b>{}</b> : {}</p>".format(key, request.json[key])
    except:
        pass

    try:
        for i, key in enumerate(request.form):
            if i == 0:
                output += "<br />"
                output += "<h2>Request Form</h2>"
            output += "<p><b>{}</b> : {}</p>".format(key, request.form[key])
    except:
        pass


    try:
        for i, key in enumerate(request.data):
            if i == 0:
                output += "<br />"
                output += "<h2>Request Data</h2>"
            output += "<p><b>{}</b> : {}</p>".format(key, request.data[key])
    except:
        pass

    return output


'''@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == "GET":
        try:
            tkn = request.cookies.get('x-access-token')
            userinfo = keycloak_openid.userinfo(tkn)
            #return render_template("login.html", msg="{} you are already logged in".format(userinfo['given_name']))
            #return '<h1>{} you are already logged in</h1><br /><a href="/logout">Logout</a>'.format(userinfo['given_name'])
            return redirect("/hello")
        except:
            #resp = make_response(redirect("/login"))
            return render_template("login.html", msg="")
    
    if request.method == "POST":
        try:            
            try:
                print(request.form)
                user = request.form['user']
                password = request.form['password']
                t = keycloak_openid.token(str(user),str(password))
            except Exception as e:
                return render_template("login.html", msg=e)
            resp = make_response(redirect("/hello"))
            resp.set_cookie('x-access-token', t['access_token'].encode('utf-8'))
            resp.set_cookie('x-refresh-token', t['refresh_token'].encode('utf-8'))
            return resp
        except Exception as e:
            print(e)
            return render_template("login.html", msg="Could not save cookie")'''

@app.route('/cookie/<val>')
def test_cookie(val):
    """Performs local logout by removing the session cookie."""
    try:
        try:
            resp = make_response('Old cookie:' + str(request.cookies.get('x-access-token')))
        except:
            resp = make_response('No cookie')
        resp.set_cookie('x-access-token', val.encode('utf-8'))
        resp.set_cookie('x-refresh-token', val.encode('utf-8'))
        return resp
    except Exception as e:
        print(e)
        return 'Could not set cookie'

@app.route('/account')
def account():
    return redirect('http://localhost:8080/auth/realms/alchemybox/account/')

@app.route('/logout')
@token_required
def logout(current_user, refresh_token):
    """Performs local logout by removing the session cookie."""

    keycloak_openid.logout(refresh_token)
    return 'Hi, you have been logged out! <a href="/">Return</a>'


@app.route('/hello', methods=['GET'])
@token_required
def hello_api(current_user):
    """OAuth 2.0 protected API endpoint accessible via AccessToken"""

    return '<h2>Hello {}</h2><br />You are logged in!<br /><a href="/logout">Logout</a>'.format(current_user['name'])


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")