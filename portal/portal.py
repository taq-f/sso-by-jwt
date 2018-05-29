# -*- coding: utf-8 -*-

"""ポータル

提供する機能は以下

* ログイン情報（ログインIDとパスワード）を受け取りユーザー認証を行う。
* 認証OKの場合、ユーザー情報を含めたトークンを発行する。
"""

from collections import namedtuple
from datetime import datetime, timedelta
import jwt
import logging
from logging.handlers import RotatingFileHandler
import os
import random
import string
from flask import (Flask, jsonify, make_response, render_template, request, redirect,
                   session)


App = namedtuple('App', ('id', 'url', 'logourl', 'caption'))


User = namedtuple('User', ('loginid', 'password', 'apps'))


APPS = [
    App('app1', 'http://localhost:5001', 'http://localhost:5001/static/app.jpg', '蛙（かえる）とは、脊椎動物亜門・両生綱・無尾目（カエル目）に分類される動物の総称。古称としてかわず（旧かな表記では「かはづ」）などがある。'),
    App('app2', 'http://localhost:5002', 'http://localhost:5001/static/app.jpg', 'マレーバク（馬来獏）は、哺乳綱ウマ目（奇蹄目）バク科バク属に分類される奇蹄類。タイの山岳民族の間では神が余りものを繋ぎ合わせて創造した動物とされた。'),
]


USERS = [
    User('user1', 'user1pwd', ['app1', 'app2']),
    User('user2', 'user2pwd', ['app1']),
    User('user3', 'user3pwd', ['app2']),
]


JWT_SECRET = 'secret'


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


def create_token(user):
    """ログイン情報からトークンを生成する"""
    payload = {
        'loginId': user.loginid,
        'apps': user.apps,
    }

    encoded = jwt.encode(payload, JWT_SECRET, algorithm='HS256')

    return encoded.decode('utf-8')


def is_valid_credential(loginid, password):
    """有効なログイン情報かの検査"""
    u = find_user(loginid)
    if not u:
        return False
    if u.password != password:
        return False
    return True


def parse_token():
    """"""
    def decode(token):
        if not token:
            return None
        try:
            return jwt.decode(token.encode('utf-8'),
                              JWT_SECRET, algorithms=['HS256'])
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
    """"""
    if request.endpoint in app.config['IGNORE_SESSION_CHECK']:
        return

    if parse_token():
        return

    return redirect('/login')


@app.after_request
def set_token(res):
    if request.endpoint == 'login':
        return res
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


@app.route('/api/has_token', methods=['GET'])
@skip_session_check
def has_token():
    """inspect token that the user has"""
    param = parse_token()
    if param:
        return jsonify(True)
    else:
        return jsonify(False)


@app.route('/api/token', methods=['POST'])
@skip_session_check
def api_token():
    """トークン取得

    パラメータ

    {
        "loginid": "ログインID",
        "password: "パスワード"
    }
    """
    body = request.get_json(silent=True)

    if not body:
        return make_response('couldn\'t parse the given body as json', 400)

    loginid = body.get('loginid')
    password = body.get('password')
    if not is_valid_credential(loginid, password):
        return make_response('invalid credential', 400)

    user = find_user(loginid)
    token = create_token(user)
    return jsonify(token)


@app.route('/login', methods=['GET'])
@skip_session_check
def show_login_page():
    """ログインページ"""
    return render_template('login.html')


@app.route('/login', methods=['POST'])
@skip_session_check
def login():
    """ログインPOST処理"""
    loginid = request.form.get('loginid')
    password = request.form.get('password')

    if not is_valid_credential(loginid, password):
        message = 'ログインID、またはパスワードが違います。'
        return render_template('login.html', message=message, loginid=loginid)

    user = find_user(loginid)
    token = create_token(user)

    res = make_response(redirect('/'))
    max_age = 60 * 60 * 24 * 1
    expires = int(datetime.now().timestamp()) + max_age
    res.set_cookie('token', value=token, max_age=max_age,
                   expires=expires, path='/')

    return res


@app.route('/', methods=['GET'])
def menu():
    """Handler for menu page"""
    token = read_token()
    param = parse_token()
    return render_template('menu.html', token=token, all_apps=[{'id': x.id, 'url': x.url, 'logourl': x.logourl, 'caption': x.caption} for x in APPS], **param)


# ******************************************************************************
# その他、デモにそれほど関係ないもの
# ******************************************************************************


def find_user(loginid):
    """ログインIDからユーザーを検索する"""
    for u in USERS:
        if loginid == u.loginid:
            return u
    return None


@app.route('/api/users', methods=['GET'])
@skip_session_check
def get_users():
    """ユーザー一覧の取得"""
    return jsonify(
        [{'loginid': x.loginid, 'password': x.password, 'apps': x.apps}
            for x in USERS]
    )


@app.errorhandler(Exception)
def handle_error(error):
    """Error handler when a routed function raises unhandled error"""
    import traceback
    print(traceback.format_exc())
    return 'Internal Server Error', 500


if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)
