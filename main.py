import os
from flask import Flask, redirect, url_for, session, request, render_template
from requests_oauthlib import OAuth2Session
from peewee import *

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
    email = CharField(null=True)
    avatar_url = CharField()

    class Meta:
        table_name = 'users'


# 建立資料庫
db.connect()
db.create_tables([User], safe=True)

# 設定 GitHub OAuth2 資訊
GITHUB_CLIENT_ID = 'yourid'
GITHUB_CLIENT_SECRET = 'yoursecret'
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
                'email': user_data.get('email', None),  # 使用 get 方法，若 email 不存在，則使用 None
                'avatar_url': user_data['avatar_url']
            })

            session['user_id'] = user.id
            return redirect(url_for('profile'))

    return redirect(url_for('index'))


@app.route('/profile', defaults={'page': 1})
@app.route('/profile/<int:page>')
def profile(page):
    """顯示使用者資訊和 repositories 列表，包含分頁功能"""
    if 'user_id' in session:
        user = User.get_or_none(User.id == session['user_id'])
        if user:
            # 每頁顯示的 repositories 數量
            per_page = 20

            # 獲取使用者 repositories (分頁)
            github = OAuth2Session(GITHUB_CLIENT_ID, token=session['oauth_token'])
            response = github.get(
                f'https://api.github.com/users/{user.username}/repos?page={page}&per_page={per_page}')
            repos = response.json()

            # 計算總頁數
            total_repos = int(response.headers.get('X-Total-Count', 0))
            total_pages = (total_repos + per_page - 1) // per_page

            return render_template('profile.html',
                                   user=user,
                                   repos=repos,
                                   page=page,
                                   total_pages=total_pages,
                                   max=max,
                                   min=min)  # 傳遞 max 函數給模板
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, ssl_context="adhoc")