import json
from lib2to3.pgen2 import token
from urllib import request
from flask import Flask,request, jsonify,abort, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY']='adamtheslayer'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(80), unique=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(10))
    admin = db.Column(db.Boolean)

class TodoModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({"message": "token is missing"}),401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = db.session.query(User).filter_by(public_id=data['public_id']).first()
        except :
            return jsonify({"message":"token is invalid",
            "token":token})
        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_user(current_user):

    if not current_user.admin :
        return jsonify({"message":"you dont have permission"})

    data = User.query.all()
    output=[]
    for user in data:
        user_data = {"name":user.name,
        "admin":user.admin,
        "password":user.password,
        "public_id":user.public_id}
        output.append(user_data)
    return {"Users":output}

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_each_user(current_user,public_id):
    data = db.session.query(User).filter_by(public_id=public_id).first()
    if not data:
        abort(404,"data not exists please check your public_id")
    return jsonify({"name":data.name,
    "admin":data.admin,
    "password":data.password,
    "public_id":data.public_id})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_task(current_user,public_id):
    data = db.session.query(User).filter_by(public_id=public_id).first()
    if not data:
        abort(404, "data not exist")
    db.session.delete(data)
    db.session.commit()
    return jsonify({"message":"data deleted",
    "public_id":data.public_id})

@app.route('/user',methods=['POST'])
@token_required
def create_user(current_user):
    data = request.get_json()
    hashed_password=generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message":"user created"})

@app.route('/user/<public_id>',methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    data = db.session.query(User).filter_by(public_id=public_id).first()
    if not data :
        abort(404,"data not exists please check public_id")
    data.admin = True
    db.session.commit()
    return{"message":"user promoted"}

@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {"WWW-Authenticate":"Basic realm='Login required'"})
    user = db.session.query(User).filter_by(name=auth.username).first()
    if not user:
        return make_response('could not verify',401, {"WWW-Authenticate":"Basic realm='Login required'"})
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id':user.public_id, "exp" : datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}, app.config['SECRET_KEY'])
        return jsonify({"token":token.decode('UTF-8')})
    
    return make_response('could not verify',401, {"WWW-Authenticate":"Basic realm='Login required'"})
    
@app.route('/todo')
def get_todo():
    output=[]
    data = TodoModel.query.all()
    if not data :
        return jsonify({"no data to shown"})
    for each_data in data:
        all_data = {"id":each_data.id,
        "text":each_data.text,
        "complete":each_data.complete,
        "user_id":each_data.user_id}
        output.append(all_data)
    
    return jsonify({"Lists" : output})

@app.route('/todo/<user_id>')
def get_each_todo(user_id):
    data_each = db.session.query(TodoModel).filter_by(user_id=user_id).first()
    if not data_each :
        abort(404, 'todo not exists')
    return jsonify({"id":data_each.id,
    "text":data_each.text,
    "complete":data_each.complete,
    "user_id":data_each.user_id
    })

@app.route('/todo', methods=['POST'])
def add_todo():
    data = request.get_json()
    data_input = TodoModel(text=data['text'],complete=False, user_id=str(uuid.uuid4()))
    if not data_input:
        return jsonify({"message":"some error occur"})
    db.session.add(data_input)
    db.session.commit()
    return jsonify({"message":"todo added"})

@app.route('/todo/<user_id>', methods=['PUT'])
def update_todo(user_id):
    data = TodoModel.query.filter_by(user_id=user_id).first()
    if not data :
        return jsonify({"message":"todo list not found"})
    data.complete=True
    db.session.add(data)
    db.session.commit()
    return jsonify({"message":"todo list completed",
    "user_id":data.user_id})

@app.route('/todo/<user_id>', methods=['DELETE'])
def delete_todo(user_id):
    data = db.session.query(TodoModel).filter_by(user_id=user_id).first()
    if not data:
        return jsonify({"message":"no data found"})
    db.session.delete(data)
    db.session.commit()
    return jsonify({"message":"todo delete",
    "user_id":data.user_id})

    
if __name__ == '__main__':
    app.run(debug=True)