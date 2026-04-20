
from flask import Flask, request, make_response, redirect, url_for
import pyotp
import secrets
from datetime import datetime


app = Flask(__name__)


totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")  # can enter into Google Authenticator and sync

active_sessions = {}




def get_current_session():
    #retrieves the session token and data based on the request's session cookie
    #returns (None, None) if the cookie is missing or the session is invalid

    token = request.cookies.get('session_id')
    if not token:
        return None, None

    session = active_sessions.get(token)
    
    if not session:
        return None, None

    return token, session




def require_login():
    token, session = get_current_session()
    if not session:
        return None
    return session




@app.route('/')
def home():
    _, session = get_current_session()


    if session:
        username = session['username']
        return f'''
            <h1>Welcome {username}</h1>
            <p>Balance: $8,421.17</p>
            <p>Savings: $13,902.44</p>
            <ul>
                <li><a href="/account">Account Overview</a></li>
                <li><a href="/transactions">Recent Transactions</a></li>
                <li><a href="/security">Security Settings</a></li>
                <li><a href="/logout">Logout</a></li>
            </ul>
        '''


    return '''
    <div style="display: flex; justify-content: center; align-items: center; height: 100vh; flex-direction: column;">
        <h2>Bank378 Login</h2>
        <form action="/login" method="post">
            User: <input name="user"><br>
            Pass: <input type="password" name="pw"><br>
            <input type="submit" value="Login">
        </form>
    </div>
    '''




@app.route('/login', methods=['POST'])
def login():
    if request.form.get('user') == 'admin' and request.form.get('pw') == 'password':
        return '''
        <div style="display: flex; justify-content: center; align-items: center; height: 100vh; flex-direction: column;">
            <h2>MFA Required</h2>
            <p>Enter the 6-digit code from your app:</p>
            <form action="/verify" method="post">
                Code: <input name="code"><br>
                <input type="submit" value="Verify">
            </form>
        </div>
        '''
    return "Failed login", 401




@app.route('/verify', methods=['POST'])
def verify():
    user_code = request.form.get('code')


    # can use actual code but 123456 is allowed for class demo consistency
    if totp.verify(user_code) or user_code == "123456":
        new_token = secrets.token_hex(16)
        active_sessions[new_token] = {
            'username': 'admin',
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': request.remote_addr,
        }


        resp = make_response("MFA Success! <a href='/'>Enter Vault</a>")
        resp.set_cookie('session_id', new_token, httponly=True)
        return resp


    return "Invalid MFA Code", 401




@app.route('/account')
def account():
    session = require_login()
    if not session:
        return redirect(url_for('home'))


    return f'''
        <h1>Account Overview</h1>
        <p>User: {session['username']}</p>
        <p>Session Created: {session['created_at']}</p>
        <p>Source IP: {session['source_ip']}</p>
        <p>Checking Balance: $8,421.17</p>
        <p>Savings Balance: $13,902.44</p>
        <a href="/">Back Home</a>
    '''




@app.route('/transactions')
def transactions():
    session = require_login()
    if not session:
        return redirect(url_for('home'))


    return '''
        <h1>Recent Transactions</h1>
        <ul>
            <li>Payroll Deposit: +$2,150.00</li>
            <li>Rent Payment: -$1,700.00</li>
            <li>Utility Bill: -$142.19</li>
            <li>Wire Transfer Hold Pending Review</li>
        </ul>
        <a href="/">Back Home</a>
    '''




@app.route('/security')
def security():
    session = require_login()
    if not session:
        return redirect(url_for('home'))


    return '''
        <h1>Security Settings</h1>
        <p>Password last changed: 12 days ago</p>
        <p>MFA Device: Authenticator App</p>
        <p>Trusted Browser Sessions: 1</p>
        <a href="/">Back Home</a>
    '''




@app.route('/logout')
def logout():
    token, session = get_current_session()
    resp = make_response(redirect(url_for('home')))


    if token and session:
        active_sessions.pop(token, None)


    resp.set_cookie('session_id', '', expires=0)
    return resp




if __name__ == '__main__':
    app.run(port=5000)


