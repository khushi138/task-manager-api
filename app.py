from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
import requests
import redis
from dotenv import load_dotenv
from sqlalchemy import Index

# Load environment variables
load_dotenv()

# Initialize the Flask app
app = Flask(__name__)

# Setup the database connection
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database, bcrypt, JWT, and Redis
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Initialize Redis
cache = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    completed = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('tasks', lazy=True))

# Create index on user_id for faster lookups
Index('user_id_index', Task.user_id)

# Route to register a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "User already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password_hash=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User created successfully"}), 201


# Route to login and get a JWT token
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity={'username': user.username})
        return jsonify({"access_token": access_token}), 200

    return jsonify({"msg": "Invalid credentials"}), 401


# Route to get user's tasks with pagination and caching
@app.route('/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    current_user = get_jwt_identity()  # Get the current logged-in user
    user = User.query.filter_by(username=current_user['username']).first()
    
    page = request.args.get('page', 1, type=int)
    per_page = 10  # You can change the number of tasks per page

    # Check Redis cache first
    cache_key = f"tasks_user_{user.id}_page_{page}"
    cached_tasks = cache.get(cache_key)

    if cached_tasks:
        return jsonify({"tasks": cached_tasks, "source": "cache"}), 200

    tasks = Task.query.filter_by(user_id=user.id).paginate(page, per_page, False)

    tasks_data = [{"id": task.id, "title": task.title, "completed": task.completed} for task in tasks.items]

    # Cache the tasks in Redis for 1 hour
    cache.setex(cache_key, 3600, jsonify({"tasks": tasks_data}).get_data(as_text=True))

    return jsonify({"tasks": tasks_data, "source": "db"}), 200


# Route to create a new task
@app.route('/tasks', methods=['POST'])
@jwt_required()
def create_task():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user['username']).first()

    data = request.get_json()
    title = data.get('title')
    description = data.get('description')

    new_task = Task(title=title, description=description, user_id=user.id)

    db.session.add(new_task)
    db.session.commit()

    # Invalidate cache for this user as new task is added
    cache.delete_pattern(f"tasks_user_{user.id}_*")

    return jsonify({"msg": "Task created successfully"}), 201


# Route to get weather data using a third-party API (OpenWeather) with caching
@app.route('/weather', methods=['GET'])
def get_weather():
    city = request.args.get('city')
    cache_key = f"weather_{city}"

    # Check if weather data is cached
    cached_weather = cache.get(cache_key)

    if cached_weather:
        return jsonify({"weather": cached_weather, "source": "cache"}), 200

    api_key = os.getenv('OPENWEATHER_API_KEY')
    url = f"http://api.openweathermap.org/data/2.5/weather?q={city}&appid={api_key}"
    
    response = requests.get(url)
    weather_data = response.json()

    if weather_data.get('cod') != 200:
        return jsonify({"msg": "City not found"}), 404

    weather_info = {
        "city": city,
        "temperature": weather_data['main']['temp'],
        "description": weather_data['weather'][0]['description']
    }

    # Cache the weather data for 1 hour
    cache.setex(cache_key, 3600, jsonify(weather_info).get_data(as_text=True))

    return jsonify({"weather": weather_info, "source": "api"}), 200


if __name__ == '__main__':
    app.run(debug=True)
