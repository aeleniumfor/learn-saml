# https://github.com/SAML-Toolkits/python3-saml を参考に実装

import os
from urllib.parse import urlparse

from flask import Flask, Request, Response, request
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

app = Flask(__name__)

# settings.jsonが必ず必要
app.config["SAML_PATH"] = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "aws_saml"
)

def prepare_request(request: Request):
    # ロードバランサの情報がrequestに入ってしまうため
    # インスタンスが直にレスポンスを受ける場合を除き下記の実装にするのがよさそう
    https_on = request.headers.get('X-Forwarded-Proto','http')
    url_data = urlparse(request.url)
    return {
        "https": "on" if https_on == "https" else "off",
        "http_host": request.host,
        "server_port": url_data.port,
        "script_name": request.path,
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
        "query_string": request.query_string,
    }

@app.route("/ok")
def OK():
    return "OK"

@app.route("/saml/meta")
def saml_aws_meta():
    # SP側のメタ情報を表示するためのエンドポイン
    req = prepare_request(request)
    saml = OneLogin_Saml2_Auth(req, custom_base_path=app.config["SAML_PATH"])
    return Response(saml.get_settings().get_sp_metadata(), mimetype="text/xml")


@app.route("/saml/acs", methods=["POST"])
def saml_aws_acs():
    # SAMLレスポンスを受け取るエンドポイント
    req = prepare_request(request)
    saml = OneLogin_Saml2_Auth(
        req,custom_base_path=app.config["SAML_PATH"],
    )
    
    saml.process_response()
    user_id = saml.get_attributes().get("UserID")
    # ログイン処理が完了していればユーザIDが表示される
    return f"{user_id}"


@app.route("/")
def login():
    # ログインするためのボタン表示
    req = prepare_request(request)
    saml = OneLogin_Saml2_Auth(req, custom_base_path=app.config["SAML_PATH"])
    login_url = saml.login()
    return f"""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>AWS SAML</title>
</head>
<body>
    <a href={login_url}>SAMLでログイン</>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
