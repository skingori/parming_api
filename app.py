import jwt
import datetime
from functools import wraps
from flask import Flask, request, jsonify, make_response, render_template, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from sqlalchemy.dialects.mysql import BIGINT

app = Flask(__name__, template_folder='templates')

MYSQL_PASSWORD = "root"  # os.environ.get('MYSQL_PASSWORD')

app.config['SECRET_KEY'] = '004f2af45d3a4e161a7dd2d17fdae47f'
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://root:{MYSQL_PASSWORD}@localhost/parking'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
marshmallow = Marshmallow(app)


class Login(db.Model):
    __tablename__ = "Login"
    Login_id = db.Column(db.Integer, primary_key=True)
    Login_username = db.Column(db.String(70), unique=True)
    Login_password = db.Column(db.String(500))
    Login_rank = db.Column(db.String(70))

    def __init__(self, login_id, login_username, login_password, login_rank):
        self.Login_id = login_id
        self.Login_username = login_username
        self.Login_password = login_password
        self.Login_rank = login_rank


class Parking(db.Model):
    __tablename__ = "Parking_Lot"
    Parking_lot_id = db.Column(BIGINT(unsigned=True), primary_key=True)
    Parking_lot_address = db.Column(db.String(500))
    Parking_lot_code = db.Column(db.String(70))

    def __init__(self, id_, address, code):
        self.Parking_lot_id = id_
        self.Parking_lot_address = address
        self.Parking_lot_code = code


class LoginSchema(marshmallow.Schema):
    class Meta:
        fields = ('Login_id', 'Login_username', 'Login_password', 'Login_rank')


class ParkingSchema(marshmallow.Schema):
    class Meta:
        fields = ('Parking_lot_id', 'Parking_lot_address', 'Parking_lot_code')


class TaskSchema(marshmallow.Schema):
    class Meta:
        fields = ('id', 'title', 'description')


task_schema = TaskSchema()
tasks_schema = TaskSchema(many=True)

login_schema = LoginSchema()
logins_schema = LoginSchema(many=True)

parking_schema = ParkingSchema()
parking_all_schema = ParkingSchema(many=True)

db.create_all()


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization']

        if not token:
            return jsonify({'message': 'a valid token is missing'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Login.query.filter_by(Login_id=data['Login_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)

    return decorator


@app.route('/registration', methods=['POST'])
def registration():
    try:
        username = request.json['email']
        password = request.json['password']
        user_id = request.json['id']
        level = "user"
        password_hash = generate_password_hash(password)
        new_user = Login(user_id, username, password_hash, level)
        db.session.add(new_user)
        db.session.commit()
        # user = login_schema.jsonify(new_user)
        # print(jsonify(user))
        body = {"token": str(user_id), "username": str(username), "error": None}
        print(body)
        status = True
        message = ""
        response = construct_response(status=status, message=message, data=body)
        return jsonify(response)
    except Exception as kk:
        message_ = "Wrong enry, check details again"
        return make_response(jsonify({"status": False, "error": message_, "message": f'{kk}'}), 200)


@app.route('/profile', methods=['POST'])
@token_required
def get_profile():
    user = Login.query.filter_by(Login_username='username').first()


@app.route('/parking', methods=['GET'])
@token_required
def parking(current_user):
    parking_all = Parking.query.all()
    result = parking_all_schema.dump(parking_all)

    print(jsonify(result))
    return jsonify(result)

# @app.route('/add_parking', methods=['GET'])
# @token_required
# def add_parking():


@app.route('/login', methods=['POST'])
def login():
    username = request.json['email']
    password = request.json['password']
    auth = request.authorization

    user = Login.query.filter_by(Login_username=username).first()
    if not auth and user is not None and check_password_hash(user.Login_password, password):
        token = jwt.encode(
            {'Login_id': user.Login_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=45)},
            app.config['SECRET_KEY'], "HS256")
        status = True
        message = "User logged in"
        body = {"token": token, "username": str(user.Login_username), "level": str(user.Login_rank)}
        response = construct_response(status=status, message=message, data=body)
        return make_response(jsonify(response), 200)
    else:
        message_ = "Username or password incorrect"
        return make_response(jsonify({"status": False, "error": message_, "message": ''}), 200)


@app.route('/admin', methods=['GET', 'POST'])
def create():
    if request.method == 'GET':
        return render_template('parking.html')

    if request.method == 'POST':
        parking_id = request.form['parking_id']
        address = request.form['address']
        code = request.form['code']
        new_user = Parking(parking_id, address, code)
        db.session.add(new_user)
        db.session.commit()
        task_schema.jsonify(new_user)
        return redirect('/admin')


def construct_response(status, message, data=None):
    return {
        "status": status,
        "message": message,
        "data": data
    }


if __name__ == '__main__':
    app.run(debug=True)