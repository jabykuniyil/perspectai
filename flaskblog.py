from logging import log
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
# from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
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
    user = Account(username=user_data['username'], full_name=user_data['full_name'], password_hash=user_data['password_hash'])
    db.session.add(user)
    db.session.commit()
    return 'Account created Successfully'

@app.route('/login', methods=['POST'])
def login():
    login_credential = request.get_json()
    return login_credential
    
@app.route('/blogs', methods=['GET', 'POST'])
def home():
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
def single_blog(id):
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