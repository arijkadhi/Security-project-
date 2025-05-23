from flask import Flask, render_template, request, jsonify
from passwordchecker import check_password_strength  

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('password.html')

@app.route('/check-password', methods=['POST'])
def check_password():
    data = request.get_json()
    password = data.get('password')
    username = data.get('username', None)

    result = check_password_strength(password, username)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
