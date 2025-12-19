from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from functools import wraps
import re

app = Flask(__name__)

# ================= CONFIG =================
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///shop.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    JWT_SECRET_KEY='CHANGE_ME_SECRET',
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(minutes=30),
    JWT_REFRESH_TOKEN_EXPIRES=timedelta(days=7)
)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ================= MODELS =================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), default='USER')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


# ================= UTILS =================
def validate_password(password):
    if len(password) < 8:
        return "Parol kamida 8 ta belgidan iborat bo‘lishi kerak"
    if not re.search(r"[A-Z]", password):
        return "Parolda kamida 1 ta katta harf bo‘lishi kerak"
    if not re.search(r"[0-9]", password):
        return "Parolda kamida 1 ta raqam bo‘lishi kerak"
    return None


def role_required(role):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            user = User.query.get(get_jwt_identity())
            if not user or user.role != role:
                return jsonify({"message": "Ruxsat yo‘q"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ================= INIT =================
@app.before_first_request
def init_db():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password=generate_password_hash('Admin123'),
            role='ADMIN'
        )
        db.session.add(admin)
        db.session.add(Product(name='Telefon', price=350))
        db.session.add(Product(name='Noutbuk', price=900))
        db.session.commit()


# ================= AUTH =================
@app.route('/api/v1/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data:
        return jsonify({"message": "JSON talab qilinadi"}), 400

    password_error = validate_password(data.get('password', ''))
    if password_error:
        return jsonify({"message": password_error}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Username band"}), 409

    user = User(
        username=data['username'],
        password=generate_password_hash(data['password'])
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Ro‘yxatdan o‘tildi"}), 201


@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()

    if not user or not check_password_hash(user.password, data.get('password')):
        return jsonify({"message": "Login yoki parol xato"}), 401

    return jsonify({
        "access_token": create_access_token(identity=user.id),
        "refresh_token": create_refresh_token(identity=user.id)
    })


@app.route('/api/v1/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    return jsonify({
        "access_token": create_access_token(identity=get_jwt_identity())
    })


# ================= PRODUCTS =================
@app.route('/api/v1/products', methods=['GET'])
@jwt_required()
def products():
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 5))

    query = Product.query.filter_by(is_deleted=False)
    pagination = query.paginate(page=page, per_page=limit, error_out=False)

    return jsonify({
        "total": pagination.total,
        "page": page,
        "items": [
            {"id": p.id, "name": p.name, "price": p.price}
            for p in pagination.items
        ]
    })


@app.route('/api/v1/products', methods=['POST'])
@role_required('ADMIN')
def create_product():
    data = request.get_json()

    product = Product(
        name=data['name'],
        price=data['price']
    )
    db.session.add(product)
    db.session.commit()

    return jsonify({"message": "Mahsulot qo‘shildi"}), 201


@app.route('/api/v1/products/<int:pid>', methods=['DELETE'])
@role_required('ADMIN')
def delete_product(pid):
    product = Product.query.get_or_404(pid)
    product.is_deleted = True
    db.session.commit()
    return jsonify({"message": "Mahsulot o‘chirildi"})


# ================= ERROR HANDLING =================
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Topilmadi"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Server xatosi"}), 500


if __name__ == '__main__':
    app.run(debug=True)
