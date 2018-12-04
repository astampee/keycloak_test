from flask import Flask, request, jsonify, render_template, make_response, redirect, url_for
import os
from keycloak import KeycloakOpenID
from functools import wraps


app = Flask(__name__)

# Configure client
keycloak_openid = KeycloakOpenID(server_url="http://keycloak:8080/auth/", client_id="alchemybox", realm_name="alchemybox", client_secret_key="e852179e-4f11-42d6-b432-f37a2c9ca627")


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if request.cookies.get('x-access-token'):
            token = request.cookies.get('x-access-token')
            refresh_token = request.cookies.get('x-refresh-token')

        if not token:
            return jsonify({'message':'Token is missing!'})
            #redirect to login

        try:
            current_user = keycloak_openid.userinfo(token)
        except:
            
            #return jsonify({'message':'Token is invalid!'}), 401
            #redirect to login
            return redirect("/login")
        
        return f(current_user, refresh_token, *args, **kwargs)
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
            return redirect("http://localhost:8080/auth/realms/alchemybox/protocol/openid-connect/auth?client_id=alchemybox&response_mode=fragment&response_type=code&login=true&redirect_uri=http://localhost:5010{}".format(url_for('hello_api')))
    
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
    

@app.route("/login", methods=['GET', 'POST'])
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
            return render_template("login.html", msg="Could not save cookie")

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
def hello_api(current_user, refresh_token):
    """OAuth 2.0 protected API endpoint accessible via AccessToken"""

    return '<h2>Hello {}</h2><br />You are logged in!<br /><a href="/logout">Logout</a>'.format(current_user['given_name'])


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")