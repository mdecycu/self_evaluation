import os
from flask import Flask, redirect, url_for, session, request, render_template
from requests_oauthlib import OAuth2Session
from peewee import *

# 設定環境變數
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# 設定 Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# 設定資料庫
DATABASE = 'github_login.db'
db = SqliteDatabase(DATABASE)


# 建立使用者模型
class BaseModel(Model):
    class Meta:
        database = db


class User(BaseModel):
    github_id = IntegerField(unique=True)
    username = CharField(unique=True)
    email = CharField()
    avatar_url = CharField()

    class Meta:
        table_name = 'users'


# 建立資料庫
db.connect()
db.create_tables([User], safe=True)

# 設定 GitHub OAuth2 資訊
GITHUB_CLIENT_ID = 'YOUR_GITHUB_CLIENT_ID'
GITHUB_CLIENT_SECRET = 'YOUR_GITHUB_CLIENT_SECRET'
AUTHORIZATION_BASE_URL = 'https://github.com/login/oauth/authorize'
TOKEN_URL = 'https://github.com/login/oauth/access_token'


# 首頁路由 - 檢查使用者是否已登入
@app.route('/')
def index():
    if 'user_id' in session:
        user = User.get_or_none(User.id == session['user_id'])
        if user:
            return redirect(url_for('profile'))
    return render_template('login.html')


# 登出路由
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# GitHub OAuth2 登入路由
@app.route('/login/github')
def login_github():
    github = OAuth2Session(GITHUB_CLIENT_ID)
    authorization_url, state = github.authorization_url(AUTHORIZATION_BASE_URL)
    session['oauth_state'] = state
    return redirect(authorization_url)


# GitHub OAuth2 回调路由
@app.route('/callback/github')
def callback_github():
    if 'oauth_state' in session:
        github = OAuth2Session(GITHUB_CLIENT_ID, state=session['oauth_state'])
        token = github.fetch_token(TOKEN_URL,
                                   client_secret=GITHUB_CLIENT_SECRET,
                                   authorization_response=request.url)
        session['oauth_token'] = token

        if 'oauth_token' in session:
            github = OAuth2Session(GITHUB_CLIENT_ID, token=session['oauth_token'])
            user_data = github.get('https://api.github.com/user').json()

            # 檢查使用者是否存在，若不存在則創建
            user, created = User.get_or_create(github_id=user_data['id'], defaults={
                'username': user_data['login'],
                'email': user_data['email'],
                'avatar_url': user_data['avatar_url']
            })

            session['user_id'] = user.id
            return redirect(url_for('profile'))

    return redirect(url_for('index'))


# 使用者資訊頁面
@app.route('/profile')
def profile():
    if 'user_id' in session:
        user = User.get_or_none(User.id == session['user_id'])
        if user:
            # 獲取使用者 repositories
            github = OAuth2Session(GITHUB_CLIENT_ID, token=session['oauth_token'])
            repos = github.get(f'https://api.github.com/users/{user.username}/repos').json()
            return render_template('profile.html', user=user, repos=repos)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)