echo "***Installing python requirements***"
pip install -r requirements.txt
echo "***Generating certificate and private key for secure websocket communication***"
openssl req -x509 -batch -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
echo "Please accept the following request from the browser"
sleep 2
xdg-open https://127.0.0.1:8392 
python3 setup_cert.py
echo "Please click \"add\" to install the Yobi extension in your browser"
sleep 2
xdg-open https://addons.mozilla.org/firefox/downloads/file/3831405/yobi-0.0.1-fx.xpi
echo "***Finished***"


