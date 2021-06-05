from functools import wraps
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime, jwt, secrets

app = Flask(__name__)
generated_key = secrets.token_urlsafe(50)
app.config['SECRET_KEY'] = generated_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:jaby@localhost/perspectai'
db = SQLAlchemy(app)

class Account(db.Model):
    username = db.Column(db.String(20), primary_key=True, nullable=False)
    full_name = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    
    def __init__(self, username, full_name, password_hash):
        self.username = username
        self.full_name = full_name
        self.password_hash = password_hash

class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post = db.Column(db.String(200))
    
    def __init__(self, post):
        self.post = post
        
@app.route('/', methods=['POST'])
def create_account():
    user_data = request.get_json()
    user = Account(username=user_data['username'], full_name=user_data['full_name'], password_hash=generate_password_hash(user_data['password_hash']))
    db.session.add(user)
    db.session.commit()
    return 'Account created Successfully'

def check_for_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'missing token'}), 403
        try:
            data = jwt.decode(token, generated_key)
            current_user = Account.query.filter_by(username=data['username']).first()
        except:
            print(token)
            return jsonify({'message' : 'invalid token'}), 403
        return func(current_user, *args, **kwargs)
    return wrapped

@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    # if not auth or not auth.username or not auth.password:
    #     return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
    user = Account.query.filter_by(username=request.json['username']).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
    if check_password_hash(user.password_hash, request.json['password_hash']):
        token = jwt.encode({'username' : user.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        print(token.encode().decode('utf-8'))
        return jsonify({'token' : token.encode().decode('utf-8')})
    
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
@app.route('/blogs', methods=['GET', 'POST'])
@check_for_token
def home(current_user):
    if request.method == 'POST':
        blog_data = request.get_json()
        blog = Blog(post=blog_data['post'])
        db.session.add(blog)
        db.session.commit()
        return jsonify(blog_data)
    all_blogs = Blog.query.all()
    output = []
    for blog in all_blogs:
        curr_blog = {}
        curr_blog['post'] = blog.post
        output.append(curr_blog)
    return jsonify(output)


@app.route('/blog/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@check_for_token
def single_blog(current_user, id):
    blog = db.session.query(Blog).filter_by(id=id).first()
    curr_blog = {}
    if blog is not None:
        if request.method == 'GET':
            curr_blog['id'] = blog.id
            curr_blog['post'] = blog.post
            return curr_blog
        elif request.method == 'PUT':
            curr_blog['post'] = request.json['post']
            blog.post = curr_blog['post']
            db.session.commit()
            return curr_blog         
        else:
            Blog.query.filter_by(id=id).delete()
            db.session.commit()
            return "Your blog has been deleted", 201
    return "url doesn't exists", 404
            
    
if __name__ == '__main__':
    app.run(debug=True)