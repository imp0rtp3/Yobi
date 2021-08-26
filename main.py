#! /usr/bin/env python3
import yara
from http.server import HTTPServer, BaseHTTPRequestHandler
from websocket_server import WebsocketServer
import json
import time
import urllib
import py7zr
import secrets
import os
import queue
import threading
import hashlib
import plyara
from git import Repo
import config


class ContentReceiver(WebsocketServer):

	'''
		This class is mainly responsible for the communication with the add on.
		The communicaiton is done with the WSS protocol.

	'''
	def __init__(self, port, **kwargs):
		self.host = '127.0.0.1'
		self.content_queue = queue.Queue()
		super().__init__(port, host=self.host, **kwargs)
		self.set_fn_new_client(self.new_client)
		self.set_fn_message_received(self.new_msg)
		self.set_fn_client_left(self.client_left)
		self.response_queue = queue.Queue()
		self.thread = threading.Thread(target=self.run_forever, daemon=True)
		self.thread.start()

	def set_reponse_queue(self, response_queue):
		self.response_queue = response_queue

	def init_response_loop(self):
		'''
			This Function sends messages from the Yarascanner to the add-on.
		'''
		while True:

			# This is a blocking call
			client, msg = self.response_queue.get()
			try:
				self.send_message(client, msg)
			except Exception as e:
				print(f"[***] Problem with {client}: {e}")

			del msg
			# In case we want to check if processing of queue is complete 
			self.response_queue.task_done()

	def new_client(self, client, server):
		'''
			New client callback function. Terminate conneciton is connction does not come from localhost
		'''
		if not client['address'][0].startswith('127.'):
			print(f'[****] Someone tried to connect from a remote computer {client["address"][0]}! Terminating connection')
			client['handler'].finish()
			return
		print("[**] New client")

	def client_left(self, client, server):
		print("[**] Client left")

	def new_msg(self, client, server, msg):
		'''
			new messsage callback funciton, try to load it as json and put is queue for yarascanner to process
		'''

		try:
			msg = json.loads(msg)
		except:
			print("[***] This message from Client {} can't be parsed as json: {}".format(client, msg[:30].decode('utf-8')))
			return
		for url in msg:
			self.content_queue.put((url, msg[url], client))			
		del msg
			
class YaraScanner(object):

	'''
		Module handling the parsing and running of the yara rules
	'''

	def __init__(self, content_queue):
		
		# Basic initial scanned file object
		self.DEFAULT_DOCSCAN_DICT = {'is_match' : False, 'matches': [], 'urls': []}

		# Dictionary of files scanned by SHA256, to avoid runnning yara on same file twice
		self.documents_scanned = dict()

		# Queue that the ContentReceiver fills with webrequests intercepted by the add-on
		self.content_queue = content_queue

		# Queue filled by Yarascanner of messages that the contentReceiver needs to send
		self._messages_qu = queue.Queue()

		# Yara parser for extracting metadata
		self._plyara_parser = plyara.Plyara()
		raw_yara_rules = self.get_yara_rules()

		# Parsed Rules
		prsd_r = self._plyara_parser.parse_string(raw_yara_rules)

		# The yara-python module gives the metadata in a really difficult way, I preferred just parsing
		# the rules seperately and the accessing the metadata through this dict.
		self._metadata_by_rule_name = {i['rule_name']: i.get('metadata', []) for i in prsd_r}

		# Compiled rules
		self.rules = yara.compile(source= raw_yara_rules)

		if not os.path.exists(config.MALICIOUS_OUTPUT_PATH):
			os.mkdir(config.MALICIOUS_OUTPUT_PATH)

		# yara worker, started as a thread so main() can continue
		self.thread = threading.Thread(target=self.yara_worker, daemon=True)		
		self.thread.start()

	def _is_needed_rule(rule):
		# Could be used to take javascript rules from a big repo
		name = rule['rule_name'].lower()
		if '_js_' in name or name.startswith('js_') or name.endswith('_js'):
			return True
		return False
	
	def get_yara_rules(self):
		'''
			This funciton clones a repository to local (or updates it) and then just returns
			a string with all the rules in its 'yara' directory
		'''
		all_rules = ''
		if config.USE_GIT:

			if not os.path.exists(config.GIT_RULES_PATH):
				os.mkdir(config.GIT_RULES_PATH)
			if not os.path.exists(os.path.join(config.GIT_RULES_PATH, 'yara')):
				print("[**] Cloning JS YARA rules Repo")
				Repo.clone_from(config.SIGBASE_URL, config.GIT_RULES_PATH)
			else:			
				repo = Repo(config.GIT_RULES_PATH)
				origin = repo.remote(name='origin')
				origin.pull()
			all_rules = ''
			for i in os.listdir(os.path.join(config.GIT_RULES_PATH, 'yara')):
				if i.endswith('.yar'):
					with open(os.path.join(config.GIT_RULES_PATH, 'yara', i), 'r') as yar_file:
						all_rules += yar_file.read() + '\n'

		if config.USE_CUSTOM_RULES:
			if not os.path.exists(config.CUSTOM_RULES_PATH):
				print("[***] USE_CUSTOM_RULES set but CUSTOM_RULES_PATH not found")
				return all_rules
			for i in os.listdir(config.CUSTOM_RULES_PATH):
				if i.endswith('.yar'):
					with open(os.path.join(config.CUSTOM_RULES_PATH, i), 'r') as yar_file:
						all_rules += yar_file.read() + '\n'
		return all_rules

	def get_msg_queue(self):
		return self._messages_qu

	def yara_worker(self):
		'''
			This function is actually running the rules.
		'''
		while True:

			# Blocking funciton, wait for a new file in the queue
			scan_item = self.content_queue.get()
			content_sha256 = hashlib.sha256(scan_item[1].encode('utf-8')).hexdigest()

			# Check if the file was already scanned, for efficiency
			if content_sha256 in self.documents_scanned:
				matches = self.documents_scanned[content_sha256]['matches']
			else:
				# Here the yara actually runs
				matches = self.rules.match(data=scan_item[1])
				self.documents_scanned[content_sha256] = self.DEFAULT_DOCSCAN_DICT
			if not matches:
				continue
			try:
				matches_rulenames = [i.rule for i in matches]
			except:
				matches_rulenames = matches
			self.documents_scanned[content_sha256]['is_match'] = True,
			self.documents_scanned[content_sha256]['matches'] = matches_rulenames
			self.documents_scanned[content_sha256]['urls'].append(scan_item[0])
			
			try:
				file_name = "{}_{}".format(time.time(), urllib.parse.urlparse(url).netloc).replace('.','_') + '.zip'
			except:
				file_name = str(time.time()) + ".zip"
			
			# Get metadata of the rule from the dict built earlier
			rules_with_meta = {i: self._metadata_by_rule_name[i] for i in  matches_rulenames}

			# I'm told secrets is a secure library:)
			password = ''.join([secrets.choice(config.PASS_CHARS) for _ in range(16)])
			try:
				with py7zr.SevenZipFile(os.path.join(config.MALICIOUS_OUTPUT_PATH, file_name), 'w', password=password) as enc_arch:
					enc_arch.writestr(scan_item[1], 'file.dnr')
					enc_arch.writestr(json.dumps({'url': scan_item[0], 'rules': rules_with_meta}), 'details.json')
			except Exception as e:
				print("[***] Problem: {}".format(e))
			
			# This is the message sent as-is to the add-on
			message = json.dumps(
				{
				'type': config.MSG_MATCH,
				 'data':
				 	{
				 	'url': scan_item[0], 
					'matches': rules_with_meta,
					'filepath': os.path.abspath(os.path.join(config.MALICIOUS_OUTPUT_PATH, file_name)),
					'password': password,
					'first_time': len(self.documents_scanned[content_sha256]['urls']) == 1, 
					'sha256': content_sha256
					}
				}
			)  
			self._messages_qu.put((scan_item[2], message))
			del scan_item
			self.content_queue.task_done()

def main():

	# Modes for working securely and unsecurly
	# We load first the content receiver because the YaraScanner requires the content_queue
	if config.IS_WSS:
		server = ContentReceiver(config.WS_PORT, key=config.WS_KEY, cert=config.WS_CERT)
	else:
		server = ContentReceiver(config.WS_PORT)		
	yara_scanner = YaraScanner(server.content_queue)
	server.set_reponse_queue(yara_scanner.get_msg_queue())
	server.init_response_loop()
	server.thread.join()
	yara_scanner.thread.join()
	server.run_forever()


if __name__ == '__main__':
	main()