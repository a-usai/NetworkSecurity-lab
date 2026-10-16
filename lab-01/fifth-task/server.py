#Onion: hidden service
from flask import Flask, request

app = Flask(__name__)
last_token = ""

@app.route('/', methods=['GET'])
def index():
    return "200 OK", 200

@app.route('/claim', methods=['GET', 'POST'])
def claim():
    global last_token
    if request.method == 'POST':
        last_token = request.get_data(as_text=True)
        return "200 OK", 200
    elif request.method == 'GET':
        return last_token, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8090)