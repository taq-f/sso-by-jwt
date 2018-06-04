# 簡易シングル・サインオン by JSON Web Token

JSON Web Token (JWT) を使った簡易シングル・サインオンの仕組みのデモ。

## 現サービスのユーザー認証

現状、アプリケーションそれぞれでログイン認証の仕組みを持っており、ログイン済のユーザーか否かの判断（セッション）には主にCookieにセッションIDを保存する手法で行っている。

1. クライアントはログイン情報をサーバーに送信する
2. サーバーはセッションIDを発行し、クライアントに送り返す
    1. セッションIDと付随する情報（ログインIDなど）の対応表はサーバー側に保存する
3. ブラウザはセッションIDをCookieに保存する
4. ブラウザはサーバーにアクセスする度、セッションIDを送る
5. セッションIDを受け取ったサーバーは、そのセッションIDに紐づく情報を確認して、適切なレスポンスを返す

## 現サービスのユーザー認証の課題

もし、これらを実現しようとした場合、

* 複数サイト（異なるドメインで提供しているかもしれない）で認証を共有（シングル・サインオン）をしたい
* しかも、認証が必要なREST APIも提供したい

現状のセッション管理の仕組みではいくつか課題がある。

* 別サーバーで可動しているアプリケーション間で "ログイン済" という情報を共有できない
* REST APIでは、Cookieはクライアントにとって扱いづらい（ことが多い）

JWTによる認証を利用することで解決を図る（なるべく簡略化された方法で）。

## JSON Web Token とは

![jwt_logo](https://jwt.io/img/pic_logo.svg)

* JWT: https://jwt.io/
* JWTは**ジョット**と読む

> JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA.

* コンパクト
* トークン自体に情報が全て入っている
    * セッションCookie方式のように、セッションIDに付随する情報（ログインIDなど）をサーバー側に保つ必要はない。
* JSONオブジェクトとしてサービス間で情報のやり取りができる
* 署名がされているので内容の検証ができ、内容が信頼できる

## トークンサンプル

`{ "my": "payload" }`というデータ保持するトークン

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJteSI6InBheWxvYWQifQ.78bnGeLf_4A3mXZhStnMo6warvE1M5QTHRJClTpnS4s
```

### Header

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

アルゴリズムと種類（JWT）の情報をただBase64エンコードしただけの文字列

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### Payload

```
eyJteSI6InBheWxvYWQifQ
```

交換したいデータ（json形式）をBase64エンコードしただけの文字列

```json
{
  "my": "payload"
}
```

### Verify Signature

```
78bnGeLf_4A3mXZhStnMo6warvE1M5QTHRJClTpnS4s
```

検証用署名。ヘッダとPayloadからこの署名を生成する際、利用者が知らないsecretを含めることにより、改ざんの検知ができる。

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

## JWTを使った認証の流れ（単一サービスだったら）

まずは、今でのようにユーザー認証の仕組みとデータ提供の仕組み両方を持つWebアプリでどのようにJWTベースの認証が行えるか。

![jwt_logo](https://cdn.auth0.com/content/jwt/jwt-diagram.png)

JWT公式Webサイトより

## JWTを使ったシングル・サインオンの流れ

### 登場人物

* 認証サービス
  * ユーザーのログイン情報を知っている
  * ユーザー認証を行い、トークンを発行できる（JWT!）
  * ユーザーがどのサービスをできるか知っている

* サービスA
  * ユーザーのログイン情報は知らない
    * ログインIDとパスワードを送られても認証することはできない
  * 認証サービスから発行された、"サービスAを使える人だよ" と書かれたトークンを持ってきたユーザーを受け入れる
    * 実際にサービスAを使えるユーザーかどうかは知らないし気にしない

* サービスB
  * ユーザーのログイン情報は知らない
    * ログインIDとパスワードを送られても認証することはできない
  * 認証サービスから発行された、"サービスBを使える人だよ" と書かれたトークンを持ってきたユーザーを受け入れる
    * 実際にサービスBを使えるユーザーかどうかは知らないし気にしない

* ユーザーX
    * ログインを1回しさえすればサービスAもサービスBも使いたい

### どのようなやり取りをすればよいか

![flow](assets/flow.png)

ユーザーは、認証サービスにログイン情報を送ってトークンを取得する。



```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dpbmlkIjoidF9mdWppaGFyYSIsInNlcnZpY2VzIjpbInNlcnZpY2VBIl19.8dJGl0hxmi22lmqxWR9mO9kqTZwMWrqrkOdSWVD_b34
```

```json
{
    "loginid": "my_login_id",
    "services": ["serviceA"],
    "exp": 1300819380
}
```

そのトークンを持ってサービスAにアクセスする。

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ...
```

## その他

### GeneXus Access Manager (GAM) でいいのでは？

TODO

### トークンの中身は閲覧可能

トークンは暗号化されている訳ではありません。なので、機密情報をトークンに含めることはできません。

暗号化されていないということは、トークンを受け取ったユーザーが内容を書き換えることができてしまいます（例えば、PayloadのユーザーIDを書き換えて他のユーザーになりすまそうとしたり、権限をadminに書き換えて本来閲覧できない情報を見ようとしたり）。しかしトークンには、ユーザーが知らない文字列を使って作られた署名がついています。Payloadを書き換えても、ユーザーはこの署名を作ることができないので、サーバー側ではPayloadと署名の不一致から改ざんの検知ができます。

## デモアプリの起動の仕方






