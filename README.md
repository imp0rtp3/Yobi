# Yobi

## Yara Based Detection for web browsers

## System Requirements
Yobi requires python3 and and right now supports only firefox and other Gecko-based browsers.

## Installation

### Automatic Installation (Linux Only)

```
cd Yobi-master/
./install.sh
```

### Manual Installation
1. Run:
```cd Yobi-master/
pip install -r requirements.txt`
# Create certificate and key used for the WSS communicaitons
openssl req -x509 -batch -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes 
python3 setup_cert.py
```
2. Open Firefox and type in the address bar `https://127.0.0.1:8392`. Click "Advanced"-> "Accept the Risk and Continue"

## Running
1. run `python3 main.py`
2. open `about:debugging#/runtime/this-firefox` in firefox, click "Load Temporary Add-on...", browse to Yobi-master/addon and select `manifest.json`

## Yobi's Inner Workings
Yobi is separated into two components - a browser extension and a python script.
They communicate through WSS protocol. Self-signed certificates need to be created in order for the protocol to function. The alternative of using the unencrypted websocket protocol would allow anyone intercepting loopback traffic to intercept decrypted https content of the browsetr.

### Why not run everything in the browser?

I am not aware of any maintained Yara engine able to run in the browser, through webassembly or JS.

## Continuing Development
This version is still very basic and should serve as a prototype. Please open issues and pull request for new features or bug you encounter.


