# Yobi

***Yara Based Detection for web browsers***

## System Requirements

Yobi requires python3 and and right now supports only firefox and other Gecko-based browsers.

## Installation

### Automatic Installation (Linux Only)

```
git clone https://github.com/imp0rtp3/Yobi/
cd Yobi/
chmod +x install.sh
./install.sh
```

### Manual Installation

1. Run:
```
git clone https://github.com/imp0rtp3/Yobi/
cd Yobi/
pip install -r requirements.txt
# Create certificate and key used for the WSS communicaitons
openssl req -x509 -batch -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes 
python3 setup_cert.py
```
2. Open Firefox and type in the address bar `https://127.0.0.1:8392`. Click "Advanced"-> "Accept the Risk and Continue"
3. open https://addons.mozilla.org/firefox/downloads/file/3831405/yobi-0.0.1-fx.xpi to install the Yobi add-on signed by mozilla.

## Running

1. run `python3 main.py`

## YARA rules

YARA rules are fetched from a repository of JS rules I created: [js-yara-rules](https://github.com/imp0rtp3/js-yara-rules/). The repo consists of free JS rules I found on the internet and some I wrote myself. Feel free to create pull requests for additional rellevant rules. 
The repository can be changed in `config.py`

Additionally, you can add your own rules by setting `USE_CUSTOM_RULES=True` and `CUSTOM_RULES_PATH` to a path containing your yara rules in `config.py`.

## Yobi's Inner Workings

Yobi is separated into two components - a browser extension and a python script.
They communicate through WSS protocol. Self-signed certificates need to be created in order for the protocol to function. The alternative of using the unencrypted websocket protocol would allow anyone intercepting loopback traffic to intercept decrypted https content of the browsetr.

### Why not run everything in the browser?

I am not aware of any maintained Yara engine able to run in the browser, through webassembly or JS.

## Continuing Development

This version is still very basic and should serve as a prototype only. Please open issues and pull request for new features or bugs you encounter.

## Contact and Feedback

Contact me via twitter - [@imp0rtp3](https://twitter.com/imp0rtp3/)

## Screenshots

![Yobi alerts Dashboard](https://raw.githubusercontent.com/imp0rtp3/Yobi/main/imgs/scr1.png)
