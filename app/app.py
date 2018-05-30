"""Flask app boilerplate"""

# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
import jwt
import os
import random
import string
from flask import (Flask, jsonify, make_response, redirect, render_template, request,
                   session)


# JWTの署名に使用されるシークレット
# このシークレットを知っていればトークンのpayloadが改ざんされていないか確認できる
JWT_SECRET = '気高く、強く、一筋に'


# 認証サービス + それを使うアプリ2つ以上の構成を取りたいので、
# デモのアプリケーション情報が環境変数で指定されていない場合は続行不可
APP_ID = os.getenv("JWT_DEMO_APP_ID")
PORT = int(os.getenv("JWT_DEMO_APP_PORT"))


# 認証を行う必要のあるWebアプリケーションのURL
AUTH_APP_URL = 'http://localhost:5000'


def parse_token():
    """トークンをパースする"""
    token = read_token()

    if not token:
        return None

    try:
        param = jwt.decode(token.encode('utf-8'),
                           JWT_SECRET, algorithms=['HS256'])
    except jwt.exceptions.DecodeError:
        return None

    return param


def read_token():
    """トークン読み込み

    以下の順でトークンが渡されているか確認し、最初に見つけたトークンを採用する。

    1. POSTリクエストのフォーム（token）
    2. Authorizationヘッダ
    3. Cookie（token）
    """
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

# ******************************************************************************
# Web
# ******************************************************************************

# *************************************
# Before each requst
# *************************************


@app.before_request
def validate_token():
    """認証が必要なページ/apiにアクセスした際のトークンチェック"""
    if request.endpoint in app.config['IGNORE_SESSION_CHECK']:
        return

    param = parse_token()
    if not param:
        # トークンが見つからない場合、認証を行うべきサービスに丸投げ
        return redirect(AUTH_APP_URL)

    # トークンを持っていたとしてもこのアプリケーションへのアクセスがあるかを
    # 確認しなければならない
    if APP_ID not in param.get('apps'):
        return redirect('/unauthorized')

    return


# *************************************
# After each requst
# *************************************


@app.after_request
def set_token_in_cookie(res):
    """Cookieへのトークンの保存

    一度送られてOKだったトークン情報はCookieに入れてブラウザからのアクセスに対応する。
    """
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
    """トップページ"""
    param = parse_token()
    return render_template('index.html', app=APP_ID, **param)


@app.route('/unauthorized', methods=['GET', 'POST'])
@skip_session_check
def unauthorized():
    """Handler for unauthorized users"""
    param = parse_token()
    return render_template('unauthorized.html', **param)


# ******************************************************************************
# その他、デモにそれほど関係ないもの
# ******************************************************************************


@app.errorhandler(Exception)
def handle_error(error):
    """Error handler when a routed function raises unhandled error"""
    import traceback
    print(traceback.format_exc())
    return 'Internal Server Error', 500


if __name__ == '__main__':
    app.run(host='localhost', port=PORT, debug=True)
