import random
import string
import validators as validators
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from jwt import DecodeError
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'Th1s1ss3cr3t'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://///Users/olivier.soulet/workspace/tinyurl/test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.String, primary_key=True, autoincrement=False)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)


class Urls(db.Model):
    id = db.Column(db.String, primary_key=True, autoincrement=False)
    user_id = db.Column(db.String(255))
    url = db.Column(db.String(2048))


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, 'Th1s1ss3cr3t', algorithms=["HS256"])
            current_user = Users.query.filter_by(id=data['id']).first()
        except DecodeError:
            return jsonify({'message': token})

        return f(current_user, *args, **kwargs)

    return decorator


@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'registered successfully'})


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = Users.query.filter_by(name=auth.username).first()

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})

    return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/urls', methods=['GET'])
def get_all_urls():
    urls = Urls.query.all()

    result = []

    for url in urls:
        url_data = {'hash': url.id, 'url': url.url}
        result.append(url_data)

    return jsonify({'urls': result})


@app.route('/shortener', methods=['POST', 'GET'])
@token_required
def shorten_url(current_user):
    data = request.get_json()

    if not validators.url(data['url']):
        return jsonify({'message': 'invalid given url'})

    hash = UrlHash.get_hash(data['url'])
    if hash:
        return jsonify({'message': hash})

    hash = UrlHash.generate_hash()

    new_url = Urls(id=hash, user_id=current_user.id, url=data['url'])
    db.session.add(new_url)
    db.session.commit()

    return jsonify({'message': hash})


@app.route('/<hash>', methods=['POST', 'GET'])
def redirect(hash):
    url = Urls.query.filter_by(id=hash).first()

    return jsonify({'redirection': url.url})


class UrlHash:
    @staticmethod
    def get_hash(url):
        url = Urls.query.filter_by(url=url).first()

        if url:
            return url.id

        return False

    @staticmethod
    def generate_hash():
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(5))


if __name__ == '__main__':
    app.run(debug=True)
