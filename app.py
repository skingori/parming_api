from email import message
from webbrowser import get
import jwt
import datetime
from datetime import datetime as dt
from functools import wraps
from flask import Flask, request, jsonify, make_response, render_template, redirect
from marshmallow_sqlalchemy import auto_field
from pymysql import Timestamp
from sqlalchemy import TIMESTAMP, DateTime, exists
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from sqlalchemy.dialects.mysql import BIGINT
from sqlalchemy.sql import func

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

class Reservation(db.Model):
    __tablename__ = "Parking_Slot_Reservation"
    Reservation_slot_id = db.Column(db.Integer , primary_key=True, autoincrement=True)
    Parking_slot_reservation_duration = db.Column(db.String(100))
    Parking_slot_reservation_vehicle_category_id = db.Column(BIGINT(unsigned=True))
    Parking_slot_reservation_Parking_lot_id = db.Column(BIGINT(unsigned=True))
    Parking_slot_reservation_driver_id = db.Column(BIGINT(unsigned=True))
    Parking_slot_reservation_booking_date = db.Column(db.DateTime, default=datetime.datetime.now)
    Parking_slot_reservation_start_timestamp = db.Column(TIMESTAMP, nullable=False, server_default=func.now())
    Parking_slot_reservation_vehicle_reg_no = db.Column(db.String(100))
    
    def __init__(self, duration, category, lot, driver, date, reg):
        self.Parking_slot_reservation_duration = duration
        self.Parking_slot_reservation_vehicle_category_id = category
        self.Parking_slot_reservation_Parking_lot_id = lot
        self.Parking_slot_reservation_driver_id = driver
        self.Parking_slot_reservation_booking_date = date
        self.Parking_slot_reservation_vehicle_reg_no = reg
        
class Slot(db.Model):
    __tablename__ = "Parking_Slip"
    Parking_slip_id = db.Column(db.Integer , primary_key=True, autoincrement=True)
    Parking_slip_entry_time = db.Column(TIMESTAMP, nullable=False, server_default=func.now())
    Parking_slip_exit_time = db.Column(db.DateTime, default=datetime.datetime.now)
    Parking_slip_basic_cost = db.Column(db.String(100))
    Parking_slip_penalty = db.Column(db.String(100))
    Parking_slip_total_cost = db.Column(db.String(100))
    Parking_slip_parking_slot_reservation_id = db.Column(BIGINT(unsigned=True))
    
    def __init__(self, exit, basic, penalty, total, reservation):
        self.Parking_slip_exit_time = exit
        self.Parking_slip_basic_cost = basic
        self.Parking_slip_penalty = penalty
        self.Parking_slip_total_cost = total
        self.Parking_slip_parking_slot_reservation_id = reservation
        

class SlotSchema(marshmallow.Schema):
    class Meta:
        fields = ('Parking_slip_id', 'Parking_slip_entry_time', 'Parking_slip_exit_time', 'Parking_slip_basic_cost', 'Parking_slip_penalty', 'Parking_slip_total_cost', 'Parking_slip_parking_slot_reservation_id')

class ReservationSchema(marshmallow.Schema):
    class Meta:
        fields = ("Reservation_slot_id", "Parking_slot_reservation_duration", "Parking_slot_reservation_vehicle_category_id", "Parking_slot_reservation_Parking_lot_id", "Parking_slot_reservation_driver_id", "Parking_slot_reservation_booking_date", "Parking_slot_reservation_start_timestamp", "Parking_slot_reservation_vehicle_reg_no")
        
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

reservation_schema = ReservationSchema()
reservations_schema = ReservationSchema(many=True)

slot_schema = SlotSchema()
slots_schema = SlotSchema(many=True)

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
        stmt = exists().where(Reservation.Parking_slot_reservation_Parking_lot_id == Parking.Parking_lot_id, Reservation.Parking_slot_reservation_booking_date > dt.now())
        q = db.session.query(Parking).filter(~stmt)
        result = parking_all_schema.dump(q)
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
def edit_vehicle(curent_user):
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
        res_ = ve_schema.dump(all_data)
        res = construct_response(status=True, message="", data=res_)
        return make_response(jsonify(res), 200)
    except Exception as ex:
        message = "Wrong enry, check details again"
        res = construct_response(status=False, message=message, error=f'{ex}')
        return make_response(jsonify(res), 200)


@app.route('/vehicle/del', methods=['DELETE'])
@token_required
def delete_vehicle(current_user):
    try:
        if request.method == 'DELETE':
            data = request.get_json()
            if data.get('vehicle_id'):
                id = data['vehicle_id']
                all_data = Vehicle.query.get(id)
            db.session.delete(all_data)
            db.session.commit()
            res_ = vehicle_category_schema.dump(all_data)
            res = construct_response(status=True, message="", data=res_)
            return make_response(jsonify(res), 200)
    except Exception as ex:
            message = "Wrong enry, check details again"
            res = construct_response(status=False, message=message, error=f'{ex}')
            return make_response(jsonify(res), 200)

@app.route('/reservation', methods=['POST'])
@token_required
def reservation(current_user):
    try:
        get_current_date_time = dt.now()
        date_time_format = "%d-%m-%Y %H:%M:%S.%f"
        timestampStr = dt.strptime(get_current_date_time.strftime(date_time_format), date_time_format)
        if request.json['reservation_parking']:
            time_gotten = request.json['reservation_date']
            future_date_time_ob =  dt.strptime(time_gotten, date_time_format)
            # Get interval between two timstamps as timedelta object
            diff = future_date_time_ob - timestampStr
            # Get interval between two timstamps in hours
            # to 2 decimal places
            reservation_duration = divmod(diff.total_seconds(), 60)[0] # reservation_duration in hours
            reservation_vehicle = request.json['reservation_vehicle']   # reservation_vehicle
            reservation_driver = request.json['reservation_driver'] # reservation_driver
            reservation_parking = request.json['reservation_parking']   # reservation_parking
            reservation__category = request.json['reservation__category'] # reservation__category
            new_reservation = Reservation(reservation_duration, reservation__category, reservation_parking, reservation_driver, future_date_time_ob, reservation_vehicle)
            db.session.add(new_reservation)
            db.session.commit()
            res = reservation_schema.dump(new_reservation)
            return construct_response(status=True, message="", data=res)
    except Exception as ex:
        return jsonify({'message': 'Wrong enry, check details again', 'error': f'{ex}'})

@app.route('/reservations', methods=['GET'])
@token_required
def reservations(current_user):
    try:
        reservations = Reservation.query.all()
        result = reservations_schema.dump(reservations)
        res = construct_response(status=True, message="", data=result)
        return make_response(jsonify(res), 200)
    except Exception as ex:
        res = construct_response(status=False, message="", error=f'{ex}')
        return make_response(jsonify(res), 200)

@app.route('/clear_reservation', methods=['POST'])
@token_required
def clear_reservation(current_user):
    try:
        if request.json['reservation_id']:
            r_id = request.json['reservation_id']
            reservation = Reservation.query.get(r_id)
            reservation.Parking_slot_reservation_booking_date = dt.now()
            db.session.add(reservation)
            db.session.commit()
            res = reservation_schema.dump(reservation)
            return construct_response(status=True, message="", data=res)
    except Exception as ex:
        message = "Wrong enry, check details again"
        res = construct_response(status=False, message=message, error=f'{ex}')
        return make_response(jsonify(res), 200)
    
@app.route('/confirm_parking', methods=['POST'])
@token_required
def confirm_parking(current_user):
    try:
        reservation_id = request.json['reservation_id']
        exit_time = request.json['exit_time']
        basic_cost = request.json['basic_cost']
        slip_penalty  = request.json['slip_penalty']
        total_cost = request.json['total_cost']
        new_confirm = Slot(exit=exit_time, basic=basic_cost, penalty=slip_penalty, total=total_cost, reservation=reservation_id)
        db.session.add(new_confirm)
        db.session.commit()

        res = slot_schema.dump(new_confirm)
        return construct_response(status=True, message="", data=res)
    except Exception as ex:
        return jsonify({'message': 'Wrong enry, check details again', 'error': f'{ex}'})

def construct_response(status, message, error=None, data=None):
    return {
        "status": bool(status),
        "message": str(message),
        "data": data,
        "error": str(error)
    }


if __name__ == '__main__':
    app.run(debug=True)
