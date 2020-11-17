from flask import Flask, abort
from flask import request
from py_jwt_validator import PyJwtValidator, PyJwtException

app = Flask(__name__)

SCOPE = "45d6bc09-d01c-4659-be4f-38bef12bd766/.default"
SERVER = "f3211d0e-125b-42c3-86db-322b19a65a22"

@app.route("/", methods=['GET', 'POST'])
def verify_token():

    # Проверяем наличие токена
    if not request.headers.get('Authorization'):
        abort(403)

    # Забираем токен из заголовков
    str_token = request.headers['Authorization']

    # Проверяем корректен ли формат токена
    try:
        validator = PyJwtValidator(str_token, auto_verify=False)
    except:
        abort(403)

    # Валидируем токен
    try:
        payload = validator.verify(True)
    except PyJwtException as e:
        abort(403)

    # Проверяем ресурс
    if payload["payload"]["aud"] != SCOPE.split("/")[0]:
        abort(403)

    # Проверяем указанный сервер авторизации
    if payload["payload"]["iss"].split("/")[-2] != SERVER:
        abort(403)

    return "Токен верифицирован!", 200


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True, threaded=True)
