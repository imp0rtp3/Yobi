# Characters used for the password
PASS_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' 

# Path for the Git rule
GIT_RULES_PATH = "./rules_repo"


# Directory where malicious pages are saved
MALICIOUS_OUTPUT_PATH = 'suspicious_scripts'

MSG_MATCH = 1

# The port of the webshell - NEEDS TO BE CHANGED WITH THE ADD-ON!!
WS_PORT = 8392
IS_WSS = True
WS_KEY = 'key.pem'
WS_CERT = 'cert.pem'

USE_GIT = True

# URL of the github rules directory
SIGBASE_URL = "https://github.com/imp0rtp3/js-yara-rules/"

# If set, searches for additional YARA rules in CUSTOM_RULES_PATH
USE_CUSTOM_RULES = False
CUSTOM_RULES_PATH = ''