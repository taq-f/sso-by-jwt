"""Flask app boilerplate"""

# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
import jwt
import os
import random
import string
from flask import (Flask, jsonify, make_response, redirect, render_template, request,
                   session)


APP_NAME = 'App1'


def get_secret_key(app, filename='secret_key'):
    """Get, or generate if not available, secret key for cookie encryption.

    Key will be saved in a file located in the application directory.
    """
    filename = os.path.join(app.root_path, filename)
    try:
        return open(filename, 'r').read()
    except IOError:
        k = ''.join([
            random.choice(string.punctuation + string.ascii_letters +
                          string.digits) for i in range(64)
        ])
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(k)
        return k


def parse_token():
    """"""
    def decode(token):
        if not token:
            return None
        try:
            return jwt.decode(token.encode('utf-8'),
                              get_secret_key(app), algorithms=['HS256'])
        except jwt.exceptions.DecodeError:
            return None
        return None

    token = read_token()
    param = decode(token)
    if param:
        return param

    return None


def read_token():
    """"""
    token = request.form.get('token')
    if token:
        return token

    auth_header = request.headers.get('Authorization')
    token = auth_header[len('Bearer '):] if auth_header else None
    if token:
        return token

    token = request.cookies.get('token')
    if token:
        return token

    return None


def remote_addr():
    """Workaround for retriving client ip address when reverse proxy in the middle"""
    return request.access_route[-1]


# ******************************************************************************
# Decorator
# ******************************************************************************


def skip_session_check(func):
    """Register the given function into skip session list.

    It won't be wrapped.
    """
    if 'IGNORE_SESSION_CHECK' not in app.config:
        app.config['IGNORE_SESSION_CHECK'] = []
    app.config['IGNORE_SESSION_CHECK'].append(func.__name__)
    return func


# ******************************************************************************
# Initialize Application
# ******************************************************************************

app = Flask(__name__)
app.config['IGNORE_SESSION_CHECK'] = ['static']
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SECRET_KEY'] = get_secret_key(app)

# ******************************************************************************
# Web
# ******************************************************************************

# *************************************
# Before each requst
# *************************************


@app.before_request
def check_token():
    """Inspect session.

    Return 401 if session has not establised yet.
    If the endpoint (function) is in skip session list, does nothing.
    """
    if request.endpoint in app.config['IGNORE_SESSION_CHECK']:
        return

    param = parse_token()
    if not param:
        return redirect('http://localhost:5000')

    if APP_NAME not in param.get('apps'):
        return redirect('/unauthorized')

    return


# *************************************
# After each requst
# *************************************


@app.after_request
def static_cache(res):
    """Set response headers about caching for static resources

    A year later is set in this example as advised here:
    https://developers.google.com/speed/docs/insights/LeverageBrowserCaching

    It may be better to store the expiration date somewhere else and reuse it
    since this example calculate the date in every request.
    """
    if request.endpoint == 'static':
        expires = datetime.now() + timedelta(days=365)
        res.headers['Expires'] = expires.isoformat()
    return res


@app.after_request
def set_token(res):
    token = read_token()
    if token:
        max_age = 60 * 60 * 24 * 1
        expires = int(datetime.now().timestamp()) + max_age
        res.set_cookie('token', value=token, max_age=max_age,
                       expires=expires, path='/')
    return res


# *************************************
# Routes
# *************************************


@app.route('/', methods=['GET', 'POST'])
def index():
    """Handler for index page"""
    if request.method == 'POST':
        return redirect('/')
    param = parse_token()
    return render_template('index.html', **param)


@app.route('/unauthorized', methods=['GET', 'POST'])
@skip_session_check
def unauthorized():
    """Handler for unauthorized users"""
    param = parse_token()
    return render_template('unauthorized.html', **param)


@app.errorhandler(Exception)
def handle_error(error):
    """Error handler when a routed function raises unhandled error"""
    import traceback
    print(traceback.format_exc())
    return 'Internal Server Error', 500


if __name__ == '__main__':
    app.run(host='localhost', port=5001, debug=True)
