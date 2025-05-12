import json
import pytest
from app import app, db, User, Task  # Import Flask app and models

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client  # This will run the test client and allow us to make requests

@pytest.fixture
def init_database():
    # Clear the database before tests
    db.create_all()

    # Create a test user
    user = User(username="testuser", password_hash="testpassword")
    db.session.add(user)
    db.session.commit()

    # Create a test task for the user
    task = Task(title="Test Task", description="This is a test task", user_id=user.id)
    db.session.add(task)
    db.session.commit()

    yield db  # Return the database object for access during tests

    db.session.remove()
    db.drop_all()  # Clean up after tests

def test_register(client):
    # Test user registration (you can add a register endpoint in your app)
    response = client.post('/register', json={
        'username': 'newuser',
        'password': 'newpassword123'
    })
    print("Response JSON:", response.get_json())
    print("Status code:", response.status_code)
    assert response.status_code == 201
    assert b"User created successfully" in response.data

def test_login(client, init_database):
    # Test login with valid credentials
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    assert b"access_token" in response.data  # Check if the access token is returned

def test_create_task(client, init_database):
    # Test creating a new task
    login_response = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    access_token = json.loads(login_response.data)["access_token"]

    response = client.post('/tasks', json={
        'title': 'New Task',
        'description': 'Test Task'
    }, headers={'Authorization': f'Bearer {access_token}'})

    assert response.status_code == 201
    assert b"Task created successfully" in response.data

def test_get_tasks(client, init_database):
    # Test fetching tasks (authenticated)
    login_response = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    access_token = json.loads(login_response.data)["access_token"]

    response = client.get('/tasks', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    assert b"tasks" in response.data  # Check if tasks are returned
