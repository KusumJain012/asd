import numpy as npBootstrap
import pickle
import pandas as pd


# Flask utils
from flask import Flask, render_template, redirect, url_for,request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user



# Define a flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecrets!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'




# Model saved with Keras model.save()
model = pickle.load(open('autism.pkl','rb'))



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50))
    password = db.Column(db.String(80))
    mobile = db.Column(db.String(80))
    city=db.Column(db.String(50))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=6, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=6, max=80)])
    mobile = StringField('mobile', validators=[InputRequired(), Length(min=6, max=80)])
    city = StringField('city', validators=[InputRequired(), Length(min=4, max=80)])



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('aaindex'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        #error here
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password,mobile=form.mobile.data,city=form.city.data)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)



@app.route('/logout', methods=['POST','GET'])
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/aaindex', methods=['GET'])
def aaindex():
    # Main page
    return render_template('aaindex.html')

@app.route('/predict',methods=['POST'])
def predict():
    text1 = request.form['1']
    text2 = request.form['2']
    text3 = request.form['3']
    text4 = request.form['4']
    text5 = request.form['5']
    text6 = request.form['6']
    text7 = request.form['7']
    text8 = request.form['8']
    text9 = request.form['9']
    text10 = request.form['10']
    text11 = request.form['11']
    text12 = request.form['12']
    text13 = request.form['13']
    text14 = request.form['14']
    text15 = request.form['15']

 
    row_df = pd.DataFrame([pd.Series([text1,text2,text3,text4,text5,text6,text7,text8,text9,text10,text11,text12,text13,text14,text15])])
    
    #print(row_df)
    prediction=model.predict_proba(row_df)
    outpu='{0:.{1}f}'.format(prediction[0][1], 2)
    output = str(float(outpu)*100)+'%'
    if outpu>str(0.5):
        return render_template('results.html', pred=f'you are having ASD. The probability is {output}')
    else:
        return render_template('result.html',pred=f'You are safe.\n Probability of having ASD is {output}')
 
@app.route('/contactdr', methods=['POST','GET'])
def contaactdr():
    # Main page
    return render_template('contactdr.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
