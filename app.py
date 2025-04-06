from flask import Flask, request, jsonify
import requests
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import os
import threading
from concurrent.futures import ThreadPoolExecutor
app = Flask(__name__)

keys = set()

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    result = cipher.encrypt(pad(plain_text, AES.block_size))
    return result.hex()

def get_token(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        data = response.json()
        ACCESS_TOKEN = data.get("access_token")
        OPEN_ID = data.get("open_id")
        return TOKEN_MAKE(ACCESS_TOKEN, OPEN_ID)
    else:
        print("Failed to get token")

def TOKEN_MAKE(ACCESS_TOKEN, OPEN_ID):
    URL = "https://loginbp.common.ggbluefox.com/MajorLogin"
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB48',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjo5MjgwODkyMDE4LCJuaWNrbmFtZSI6IkJZVEV2R3QwIiwibm90aV9yZWdpb24iOiJNRSIsImxvY2tfcmVnaW9uIjoiTUUiLCJleHRlcm5hbF9pZCI6ImYzNGQyMjg0ZWJkYmFkNTkzNWJjOGI1NTZjMjY0ZmMwIiwiZXh0ZXJuYWxfdHlwZSI6NCwicGxhdF9pZCI6MCwiY2xpZW50X3ZlcnNpb24iOiIxLjEwNS41IiwiZW11bGF0b3Jfc2NvcmUiOjAsImlzX2VtdWxhdG9yIjpmYWxzZSwiY291bnRyeV9jb2RlIjoiRUciLCJleHRlcm5hbF91aWQiOjMyMzQ1NDE1OTEsInJlZ19hdmF0YXIiOjEwMjAwMDAwNSwic291cmNlIjoyLCJsb2NrX3JlZ2lvbl90aW1lIjoxNzE0NjYyMzcyLCJjbGllbnRfdHlwZSI6MSwic2lnbmF0dXJlX21kNSI6IiIsInVzaW5nX3ZlcnNpb24iOjEsInJlbGVhc2VfY2hhbm5lbCI6ImlvcyIsInJlbGVhc2VfdmVyc2lvbiI6Ik9CNDUiLCJleHAiOjE3MjIwNTkxMjF9.yYQZX0GeBMeBtMLhyCjSV0Q3e0jAqhnMZd3XOs6Ldk4',
        'Content-Length': '928',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'loginbp.common.ggbluefox.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }

    data = b'\x1a\x132024-12-05 11:19:55"\tfree fire(\x01:\x071.108.3BBAndroid OS 9 / API-28 (PQ3A.190801.002/eng.follow.20190916.160906)J\x08HandheldZ\x04WIFI`\xb6\nh\xc1\x06r\x03240z\x1dARM64 FP ASIMD AES | 1690 | 8\x80\x01\x9c\x0e\x8a\x01\tMali-T830\x92\x01>OpenGL ES 3.2 v1.r22p0-01rel0.b2aac5131cae69d7a0425dd51b8f9bcd\xa2\x01\x0c45.243.10.62\xaa\x01\x02en\xb2\x01 e32fabfd33fd3e5d0c19547b13727cb9\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x0fsamsung SM-T585\xea\x01@1f164b149a618e3e0c77232d08913765c7b11c3d86ee21bb541e797cd114951d\xf0\x01\x01\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\x95\xc6\x01\xe8\x03\xe2\x18\xf0\x03\xc3\x16\xf8\x03\xc4\x08\x80\x04\xe2\x18\x88\x04\x95\xc6\x01\x90\x04\xe2\x18\x98\x04\x95\xc6\x01\xc8\x04\x01\xd2\x04?/data/app/com.dts.freefireth-3oFiVA7Ro1cJB8XyS9P3RA==/lib/arm64\xe0\x04\x01\xea\x04_5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-3oFiVA7Ro1cJB8XyS9P3RA==/base.apk\xf0\x04\x03\xf8\x04\x02\x8a\x05\x0264\x9a\x05\n2019117863\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xca\x05\t@\x00L\x17S[\x0fQ0\xe0\x05\xe0\xc7\x01\xea\x05\x07android\xf2\x05\\KqsHT6p3UrvVPBdpsHgrIesEkcBBUyJoMTKmN1TEdeByKr+EN7mk+5PGnH1q7dH6WgXed2N43PtLAR7+dr7w49kJZwA=\xf8\x05\x8d\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014'
    OLD_ACCESS_TOKEN = "1f164b149a618e3e0c77232d08913765c7b11c3d86ee21bb541e797cd114951d"
    OLD_OPEN_ID = "e32fabfd33fd3e5d0c19547b13727cb9"
    data = data.replace(OLD_OPEN_ID.encode(), OPEN_ID.encode())
    data = data.replace(OLD_ACCESS_TOKEN.encode(), ACCESS_TOKEN.encode())
    Final_Payload = bytes.fromhex(encrypt_api(data.hex()))
    RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False)
    if RESPONSE.status_code == 200:
        if len(RESPONSE.text) < 10:
            raise Exception("Invalid token response")
        BASE64_TOKEN = RESPONSE.text[RESPONSE.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):-1]
        second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
        BASE64_TOKEN = BASE64_TOKEN[:second_dot_index + 44]
        return BASE64_TOKEN
    else:
        raise Exception("Failed to generate token")

def regenerate_token_periodically():
    while True:
        uid = os.getenv("3854357633")
        password = os.getenv("D4EA1C309DEF03E189F924EE2CDBF85E2B35AB9E800567143327BA1FE4F29F6E")
        token = get_token(uid, password)
        print(f"New token: {token}")
        time.sleep(7 * 60 * 60)

@app.route('/regen_token', methods=['GET'])
def regen_token():
    uid = os.getenv("UID")
    password = os.getenv("PASSWORD")
    token = get_token(uid, password)
    return jsonify({"message": "Token regenerated successfully", "token": token}), 200

@app.route('/make_key', methods=['GET'])
def make_key():
    key = request.args.get('key')
    if not key:
        return jsonify({"error": "Key parameter is missing"}), 400
    keys.add(key)
    return jsonify({"message": f"KEY '{key}' ADDED SUCCESSFULLY"}), 200

@app.route('/del_key', methods=['GET'])
def del_key():
    key = request.args.get('key')
    if not key:
        return jsonify({"error": "Key parameter is missing"}), 400
    if key in keys:
        keys.remove(key)
        return jsonify({"message": f"Key '{key}' DELETED SUCCESSFULLY"}), 200
    else:
        return jsonify({"error": f"Key '{key}' not found"}), 404

@app.route('/request', methods=['GET'])
def send_spam():
    api_key = request.args.get('api_key')
    user_id = request.args.get('uid')

    if not api_key or not user_id:
        return jsonify({"error": "Missing required parameters: api_key or uid"}), 400

    if api_key not in keys:
        return jsonify({"error": "Invalid API key"}), 403

    message = mymessage_pb2.MyMessage()
    message.field1 = 9797549324
    message.field2 = int(user_id)
    message.field3 = 22

    serialized_message = message.SerializeToString()
    encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_message)
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

    tokens = fetch_tokens()
    if not tokens:
        return jsonify({"error": "No tokens available"}), 500

    success_count = 0
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(lambda token: send_request(token, hex_encrypted_data), tokens)

    success_count = sum(1 for result in results if result)

    return jsonify({"message": f"Successfully sent {success_count} requests."}), 200

if __name__ == '__main__':
    threading.Thread(target=regenerate_token_periodically, daemon=True).start()
    app.run(debug=True, host='0.0.0.0', port=5000)