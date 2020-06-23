from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = '32843840971de3db4b7d4efa53a7241d'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db/main.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    text = db.Column(db.String(100))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


def token_requiered(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first_or_404()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/user/', methods=['GET', 'POST',])
@token_requiered
def get_all_user(current_user):
    if request.method == 'GET':
        if not current_user.admin:
            return jsonify({'message':'Cannot perform that function!'})
        users = User.query.all()
        output = []
        for user in users:
            user_data = {}
            user_data['public_id'] = user.public_id
            user_data['name'] = user.name
            user_data['password'] = user.password
            user_data['admin'] = user.admin
            output.append(user_data)
        return jsonify(output)
    elif request.method == 'POST':
        if not current_user.admin:
            return jsonify({'message':'Cannot perform that function!'})
        data = request.get_json()
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = User(publick_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"Message": "New user created!"})


@app.route('/user/<public_id>', methods=['GET', 'PUT', 'DELETE'])
@token_requiered
def get_one_user(current_user, public_id):
    if request.method == 'GET':
        if not current_user.admin:
            return jsonify({'message':'Cannot perform that function!'})
        user = User.query.filter_by(public_id=public_id).first_or_404()
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        return jsonify({'user': user_data})
    elif request.method == 'PUT':
        if not current_user.admin:
            return jsonify({'message':'Cannot perform that function!'})
        user = User.query.filter_by(public_id=public_id).first_or_404()
        user.admin = True
        db.session.commit()
        return jsonify({'message': 'Success'})
    elif request.method == 'DELETE':
        if not current_user.admin:
            return jsonify({'message':'Cannot perform that function!'})
        user = User.query.filter_by(public_id=public_id).first_or_404()
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'Successfuly deleted'})


@app.route('/login/')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Aunthenticate': 'Basic realm="Login required!"'})
    
    user = User.query.filter_by(name=auth.username).first_or_404()
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow()+datetime.timedelta(hours=12)}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token.decode('utf-8')})
    return make_response('Could not verify', 401, {'WWW-Aunthenticate': 'Basic realm="Login required!"'})


@app.route('/todo/', methods=['GET', 'POST'])
@token_requiered
def get_create_todo(current_user):
    if request.method == 'GET':
        todos = Todo.query.filter_by(user_id=current_user.id).all()
        output = []
        for todo in todos:
            todo_data = {}
            todo_data['id'] = todo.id
            todo_data['text'] = todo.text
            todo_data['complete'] = todo.complete
            output.append(todo_data)
        return jsonify(output)
    elif request.method == 'POST':
        data = request.get_json()
        new_todo = Todo(text=data['text'], complete=False, user_id=current_user.id)
        db.session.add(new_todo)
        db.session.commit()
        return jsonify({'message': 'Success! Your todo was created😊'})


@app.route('/todo/<todo_id>', methods=['GET', 'PUT', 'DELETE'])
@token_requiered
def todo(current_user, todo_id):
    if request.method == 'GET':
        todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first_or_404()
        output = []
        todo_data = {}
        todo_data['id'] = todo.id
        todo_data['text'] = todo.text
        todo_data['complete'] = todo.complete
        output.append(todo_data)
        return jsonify(output)
    elif request.method == 'PUT':
        todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first_or_404()
        todo.complete = True
        db.session.commit()
        return jsonify({'message': f'Todo {todo_id} is now compeleted'})
    elif request.method == 'DELETE':
        todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first_or_404()
        db.session.delete(todo)
        db.session.commit()
        return jsonify({'message': f'Todo {todo_id} is deleted😢'})


if __name__ == "__main__":
    app.run(host='0.0.0.0')