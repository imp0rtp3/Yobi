let scan_queue = [];
const MSG_MATCH = 1;
const MSG_ERROR = 2;
const DEF_RULES_URL = 'https://raw.githubusercontent.com/imp0rtp3/js-yara-rules/main/all_rules.yar';
const MAL_EMOJI_PATH = "icons/emoji-frown-fill.svg";
const MAL_ALERT_PATH = "icons/virus.png";

class utils {


	static sleep(ms) {
		return new Promise(resolve => setTimeout(resolve, ms));
	}

	static toHexString(byteArray) {
	// Converts a bytearray from jscl hash function to hexadecimal string
	  return Array.from(byteArray, function(byte) {
	    return ('00000000' + (byte > -1 ? (byte & 0x7FFFFFFF) : 0x100000000 + byte ).toString(16)).slice(-8);
	  }).join('');
	}

	static set_icon_malfound(){
		// Changes the icon in the top-right corner to indicate malicious item found"
		browser.browserAction.setIcon({path: MAL_EMOJI_PATH});
	}
}

class YaraScanner
{
	/*
			Module handling the parsing and running of the yara rules
	*/
	constructor(yara_module)
	{
		let self = this;
		
		// Dictionary of files scanned by SHA256, to avoid runnning yara on same file twice
		this.documents_scanned = {}

		// Queue that the ContentReceiver fills with webrequests intercepted by the add-on
		this.yara_eng = yara_module;
		// Queue filled by Yarascanner of messages that the contentReceiver needs to send
		this._messages_qu = [];
		// Yara parser for extracting metadata
		this.get_yara_rules()

		this.yara_worker_loop = setInterval(function(x){
			self.yara_worker();
		}, 100);
	}
	
	async get_yara_rules(){
	/*
		This funciton clones a repository to local (or updates it) and then just returns
		a string with all the rules in its 'yara' directory
	*/
		let response;
		const rules_url = (await browser.storage.local.get("settings")).settings.yara_rules_url || DEF_RULES_URL;
		try
		{
			response = await fetch(rules_url);
		}
		catch(e)
		{
			console.log(`[***] Problem Fetching Rules: ${e.message}`);
			await this.get_rules_from_ls();	
			return false;
		}
		if (response.ok) { // if HTTP-status is 200-299
			this.raw_yara_rules = await response.text();
			browser.storage.local.set({"raw_rules": this.raw_yara_rules});
			return true;
		}
		console.log('[***] Problem Fetching Rules - Bad Response Code');
		await this.get_rules_from_ls();
		return false;	
	}
	
	async get_rules_from_ls(){
		/*
			Get rules from localstorage - used only if the rules site is not accessible
		*/
		await browser.storage.local.get("raw_rules", function(item){
			if(item['raw_rules'].length == 0){
				clearInterval(this.yara_worker_loop)
				console.log("[***] Error - no rules saved in Localstorage, stopping Yobi!");
				throw Exception;
			}
			this.raw_yara_rules = item["raw_rules"];
		});
	}

	yara_worker(){
		/*
			This function is actually running the rules.
		*/
		while(scan_queue.length > 0){
			const scan_item = scan_queue.shift();
			const url = scan_item[0];
			const content_sha256 = utils.toHexString(sjcl.hash.sha256.hash(scan_item[1]));

			// Check if the file was already scanned, for efficiency
			if(!this.documents_scanned[content_sha256]){

				// init basic structure.
				this.documents_scanned[content_sha256] = {'is_match' : false, 'matches': {}, 'urls': []};

				// Here the yara actually runs
				const yara_matches = this.yara_eng.run(scan_item[1], this.raw_yara_rules);
				
				// Check for errors - TODO: run one time and not every time
				if (yara_matches.compileErrors.size() > 0) {
                    for (let i = 0; i < yara_matches.compileErrors.size(); i++) {
                        const compileError = yara_matches.compileErrors.get(i);
                        if (!compileError.warning) {
                            throw new OperationError(`Error on line ${compileError.lineNumber}: ${compileError.message}`);
                    	}
                    }
                }

                // Convert matchedRules libyara-wasm Object to a nice dictionary.
                for (let i = 0; i < yara_matches.matchedRules.size(); i++) {
                	let metadata = {};
                	const rule = yara_matches.matchedRules.get(i);
                	for (let j = 0; j < rule.metadata.size() ; j++) {
                		metadata[rule.metadata.get(j).identifier] =  rule.metadata.get(j).data;
                	} 
					this.documents_scanned[content_sha256]['matches'][rule.ruleName] =  metadata;
				}
			}
			if(Object.keys(this.documents_scanned[content_sha256]['matches']).length == 0){
				this.documents_scanned[content_sha256]['is_match'] = false;
				continue;
			}
			this.documents_scanned[content_sha256]['is_match'] = true;
			this.documents_scanned[content_sha256]['urls'].push(url)
			const file_path = (new URL(url).pathname) || '';
			let filename = '';
			if(file_path.length > 2) {
				// Get the last directory or file in the URL.
				// If it's https://example.com/hello/world/ - get 'world' and not '' 
				filename = file_path.split('/').slice(-1)[0] || file_path.split('/').slice(-2)[0];
			}
			const message = {
				'type': MSG_MATCH,
				'data':
				{
					'url': url, 
					'file_name' : filename,
					'matches': this.documents_scanned[content_sha256]['matches'],
					'first_time':this.documents_scanned[content_sha256]['urls'].length == 1, 
					'sha256': content_sha256,
				}
			};
			messenger.new_message(message);
			this.save_file(scan_item[1], content_sha256);
		}
	}

	save_file(data, sha256)
	{
		function setItem() {
			return;
		}
	
		function onError(error) {
	  		console.log(`[***] Error Saving File: ${error}`);
		}

		let dict = {};
		dict[`sample_${sha256}`] = btoa(encodeURIComponent(data));
		browser.storage.local.set(dict).then(setItem, onError);
	}
}

class messenger{
	
	static async new_message(data) {
		switch(data.type) {
			case MSG_MATCH:

				// Change the icon in the toolbar to the icon indicating suspisious script
				utils.set_icon_malfound();
				browser.notifications.create({
					"type": "basic",
					"iconUrl": browser.runtime.getURL(MAL_ALERT_PATH),
					"title": "Found Suspicious File!",
					"message": `Found ${Object.keys(data.data.matches).toString()} in ${data.data.url.replace('://','[:]//')}`
				});

				// Update the rule_matches browser localstorage for the popup
				browser.storage.local.get("rule_matches", function(items)
				{
						let rm = items['rule_matches'] || {};
						rm[data.data.sha256] = data.data;
						browser.storage.local.set({"rule_matches": rm});		
				});
				break;
			case MSG_ERROR:
				browser.notifications.create({
					"type": "basic",
					"iconUrl": browser.runtime.getURL(MAL_ALERT_PATH),
					"title": "Error!",
					"message": data.data.message
				});
				browser.storage.local.get("errors", function(items)
				{
						const rm = (items['errors'] || []).concat(data.data);
						browser.storage.local.set({"rule_matches": rm});		
				});
		}
	}
}


function listener(details) {
	/* This function is responsible for intercepting all rellevant requests, 
			putting it in a filequeue and also forwarding it.
	*/
	let filter = browser.webRequest.filterResponseData(details.requestId);
	let decoder = new TextDecoder("utf-8");
	let encoder = new TextEncoder();
	let data = [];

	filter.ondata = event => {
		data.push(decoder.decode(event.data, {stream: true}));
	};
	filter.onstop = event => {
		// TODO - check if we need to decode it really
		data.push(decoder.decode());
		const str = data.join("");
		filter.write(encoder.encode(str));
		filter.close();
		scan_queue.push([details.url, str]);
	};
}

function init_yobi(){

	browser.storage.local.get("settings", async function(item){
		if(!item['settings'])
		{
			await browser.storage.local.set({"settings":
				{	
					"archive_password": "infected",
					"yara_rules_url": DEF_RULES_URL   
				}
			});
		}
		new Module().then(async Module => {
			let YS = new YaraScanner(Module);
		});
	});

	// "Module" is the name of the libyara-wasm module. 
	

	// Register the listener intercepting all interesting files.
	browser.webRequest.onBeforeRequest.addListener(
		listener,	
		{
			"urls":["<all_urls>"],
			"types": ["main_frame", "script", "object", "sub_frame", "other"]
		},
		["blocking"]
	);
	
	// Check if matches have already been found and change icon accordingly
	browser.storage.local.get("rule_matches", function(item){
		if(item['rule_matches'] && Object.keys(item['rule_matches']).length > 0){
			utils.set_icon_malfound();
		}
	});
}

init_yobi();