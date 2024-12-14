from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html', title="Secure Messaging Home", heading="Welcome to Secure Messaging System")

@app.route('/encrypt', methods=['POST'])
def encrypt():
    message = request.form['message']
    encrypted_message = message[::-1]  # Example: reversing the string as encryption
    return f"Encrypted message: {encrypted_message}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)