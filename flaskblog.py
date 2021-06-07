from functools import wraps
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime, jwt, secrets, os
from werkzeug.utils import secure_filename


app = Flask(__name__)
#generating the secret_key.
generated_key = secrets.token_urlsafe(50)
app.config['SECRET_KEY'] = generated_key
#setting up the database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:jaby@localhost/perspectai'
db = SQLAlchemy(app)

#creating table for the users.
class Account(db.Model):
    __tablename__ = 'user'
    username = db.Column(db.String(20), primary_key=True, nullable=False)
    full_name = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    
    def __init__(self, username, full_name, password_hash):
        self.username = username
        self.full_name = full_name
        self.password_hash = password_hash

#creating table for the blog.
class Blog(db.Model):
    __tablename__ = 'blog'
    id = db.Column(db.Integer, primary_key=True)
    post = db.Column(db.String(200))
    archive = db.Column(db.Boolean(), default=False, nullable=False)

    def __init__(self, id, post):
        self.id = id
        self.post = post
        
#saving the files to particular folder.
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

#allowing extensions.
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

#validating the file is valid or not.
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
        
#creating account for the user and make hashing the password.
@app.route('/', methods=['POST'])
def create_account():
    user_data = request.get_json()
    user = Account(username=user_data['username'], full_name=user_data['full_name'], password_hash=generate_password_hash(user_data['password_hash'], method='sha256'))
    db.session.add(user)
    db.session.commit()
    return jsonify({
        'message' : 'New User created successfully'
    })
    
    
#to get the all users in the database.
@app.route('/users', methods=['GET'])
def all_users():
    users = Account.query.all()
    output = []
    for x in users:
        user = {}
        user['full_name'] = x.full_name
        user['username'] = x.username
        output.append(user)
    return jsonify({'users' : output})

#decorator used to call this function for every function to chek wheather the token is available or not.
def check_for_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'missing token'}), 401
        try:
            data = jwt.decode(token, generated_key)
            current_user = Account.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'message' : 'invalid token'}), 401
        return func(current_user, *args, **kwargs)
    return wrapped

#login function and generating token for each logged users with expiring time.
@app.route('/login', methods=['GET'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
    user = Account.query.filter_by(username=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
    if check_password_hash(user.password_hash, auth.password):
        token = jwt.encode({
            'username' : user.username,
            'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode()})
    
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
    
""" GET method is used to get the all blogs in the database except archived. POST method is used to create a new blog.
"""
@app.route('/blogs', methods=['GET', 'POST'])
#callling function to check the token for current user is available or not
@check_for_token
def home(current_user):
    if request.method == 'POST':
        if 'files[]' not in request.files:
            blog_data = request.get_json()
            blog = Blog(post=blog_data['post'])
            db.session.add(blog)
            db.session.commit()
            return jsonify(blog_data)
        files = request.files.getlist('files[]')
        errors = {}
        success = False
        for file in files:      
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                success = True
            else:
                errors[file.filename] = 'File type is not allowed'
        if success and errors:
            errors['message'] = 'File(s) successfully uploaded'
            resp = jsonify(errors)
            resp.status_code = 500
            return resp
        if success:
            resp = jsonify({'message' : 'Files successfully uploaded'})
            resp.status_code = 201
            return resp
        else:
            resp = jsonify(errors)
            resp.status_code = 500
            return resp
    blogs = Blog.query.filter_by(archive=False)
    output = []
    for blog in blogs:
        curr_blog = {}
        curr_blog['post'] = blog.post
        output.append(curr_blog)
    return jsonify(output)


""" GET method is for to get the particular post with respect to the id in the url. POST method is to archive the particular post. PUT method is to update the particular post. DELETE method is to delete the particular post.
"""
@app.route('/blog/<int:id>', methods=['GET', 'PUT', 'DELETE', 'POST'])
#callling function to check the token for current user is available or not
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
        elif request.method == 'DELETE':
            Blog.query.filter_by(id=id).delete()
            db.session.commit()
            return "Your blog has been deleted", 201
        elif request.method == 'POST':
            curr_blog['id'] = request.json['id']
            curr_blog['archive'] = True
            curr_blog['post'] = blog.post
            curr_blog['message'] = 'This data has been archived'
            db.session.commit()
            return curr_blog
        else:
            return jsonify({'message' : 'method doesn"t support'})
    return "url doesn't exists", 404
            
    
if __name__ == '__main__':
    app.run(debug=True)