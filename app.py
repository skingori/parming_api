from email import message
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
    __tablename__ = "login"
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
    __tablename__ = "parking_lot"
    Parking_lot_id = db.Column(BIGINT(unsigned=True), primary_key=True)
    Parking_lot_address = db.Column(db.String(500))
    Parking_lot_code = db.Column(db.String(70))

    def __init__(self, id_, address, code):
        self.Parking_lot_id = id_
        self.Parking_lot_address = address
        self.Parking_lot_code = code

class Vehicle(db.Model):
    __tablename__ = "Vehicle_category"
    Vehicle_category_id = db.Column(BIGINT(unsigned=True), primary_key=True)
    Vehicle_category_name = db.Column(db.String(100))
    Vehicle_category_desc = db.Column(db.String(500))
    Vehicle_category_daily_parking_fee = db.Column(db.String(100))
    
    def __init__(self, id_, name, desc, fee):
        self.Vehicle_category_id = id_
        self.Vehicle_category_name = name
        self.Vehicle_category_desc = desc
        self.Vehicle_category_daily_parking_fee = fee
        
class LoginSchema(marshmallow.Schema):
    class Meta:
        fields = ('Login_id', 'Login_username', 'Login_password', 'Login_rank')


class ParkingSchema(marshmallow.Schema):
    class Meta:
        fields = ('Parking_lot_id', 'Parking_lot_address', 'Parking_lot_code')

class VehicleSchema(marshmallow.Schema):
    class Meta:
        fields = ('Vehicle_category_id', 'Vehicle_category_name', 'Vehicle_category_desc', 'Vehicle_category_daily_parking_fee')
class TaskSchema(marshmallow.Schema):
    class Meta:
        fields = ('id', 'title', 'description')


task_schema = TaskSchema()
tasks_schema = TaskSchema(many=True)

login_schema = LoginSchema()
logins_schema = LoginSchema(many=True)

parking_schema = ParkingSchema()
parking_all_schema = ParkingSchema(many=True)

vehicle_category_schema = VehicleSchema()
vehicle_all_schema = VehicleSchema(many=True)

db.create_all()


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization']

        if not token:
            return jsonify({'message': 'a valid token is missing', 'status': False, 'error': 'invalid token'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Login.query.filter_by(Login_id=data['Login_id']).first()
        except Exception as ex:
            return jsonify({'message': 'token is invalid', 'error': f'{ex}'})

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
        test = login_schema.dump(new_user)
        body = {"token": str(user_id), "username": str(username), "error": ""}
        print(body)
        status = True
        message = ""
        response = construct_response(status=status, message=message, data=test)
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
    try:
        parking_all = Parking.query.all()
        result = parking_all_schema.dump(parking_all)
        res = construct_response(status=True, message="", data=result)
        print(make_response(jsonify(res), 200))
        return make_response(jsonify(res), 200)
    except Exception as ex:
        res = construct_response(status=False, message="", error=f'{ex}')
        return make_response(jsonify(res), 200)


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


# add vehicle:
@app.route('/vehicle', methods=['POST'])
@token_required
def vehicle(current_user):
    try:
        vehicle_id = request.json['vehicle_id']
        vehicle_category = request.json['vehicle_category']
        vehicle_description = request.json['vehicle_description']
        vehicle_fee = request.json['vehicle_fee']
        new_vehicle = Vehicle(vehicle_id, vehicle_category, vehicle_description, vehicle_fee)
        db.session.add(new_vehicle)
        db.session.commit()
        res = vehicle_category_schema.dump(new_vehicle)
        return construct_response(status=True, message="", data=res)
    except Exception as ex:
        return jsonify({'message': 'Wrong enry, check details again', 'error': f'{ex}'})


# get vehicles:
@app.route('/vehicles', methods=['GET'])
@token_required
def vehicles(current_user):
    try:
        vehicle_all = Vehicle.query.all()
        result = vehicle_all_schema.dump(vehicle_all)
        res = construct_response(status=True, message="", data=result)
        return make_response(jsonify(res), 200)
    except Exception as ex:
        res = construct_response(status=False, message="", error=f'{ex}')
        return make_response(jsonify(res), 200)

@app.route('/vehicle/edit', methods=['PATCH'])
@token_required
def update_todo_by_id(curent_user):
    try:
        data = request.get_json()
        if data.get('vehicle_id'):
            id = data['vehicle_id']
            all_data = Vehicle.query.get(id)
        if data.get('vehicle_category'):
            all_data.Vehicle_category_name = data['vehicle_category']
        if data.get('vehicle_description'):
            all_data.Vehicle_category_desc = data['vehicle_description']
        if data.get('vehicle_fee'):
            all_data.Vehicle_category_daily_parking_fee = data['vehicle_fee']
        db.session.add(all_data)
        db.session.commit()
        ve_schema = VehicleSchema(only=['Vehicle_category_id', 'Vehicle_category_name', 'Vehicle_category_desc', 'Vehicle_category_daily_parking_fee'])
        res = ve_schema.dump(all_data)
        res = construct_response(status=True, message="", data=res)
        return make_response(jsonify(res), 200)
    except Exception as ex:
        message = "Wrong enry, check details again"
        res = construct_response(status=False, message=message, error=f'{ex}')
        return make_response(jsonify(res), 200)


@app.route('/api/v1/todo/<id>', methods=['DELETE'])
def delete_todo_by_id(id):
    get_todo = Todo.query.get(id)
    db.session.delete(get_todo)
    db.session.commit()
    return make_response("", 204)

def construct_response(status, message, error=None, data=None):
    return {
        "status": bool(status),
        "message": str(message),
        "data": data,
        "error": str(error)
    }


if __name__ == '__main__':
    app.run(debug=True)
