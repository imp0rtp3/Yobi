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
	  return Array.from(byteArray, function(byte) {
	    return ('00000000' + (byte > -1 ? (byte & 0x7FFFFFFF) : 0x100000000 + byte ).toString(16)).slice(-8);
	  }).join('')
	}
	static set_icon_malfound(){
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
		let that = this;
		// Basic initial scanned file object
		this.DEFAULT_DOCSCAN_DICT = {'is_match' : false, 'matches': {}, 'urls': []};

		// Dictionary of files scanned by SHA256, to avoid runnning yara on same file twice
		this.documents_scanned = {}

		// Queue that the ContentReceiver fills with webrequests intercepted by the add-on
		this.yara_eng = yara_module;
		// Queue filled by Yarascanner of messages that the contentReceiver needs to send
		this._messages_qu = [];
		// Yara parser for extracting metadata
		this.get_yara_rules()

		this.yara_worker_loop = setInterval(function(x){
			that.yara_worker();
		}, 100);
	}
	
	async get_yara_rules(){
	/*
		This funciton clones a repository to local (or updates it) and then just returns
		a string with all the rules in its 'yara' directory
	*/
		let all_rules = '';
		let response;
		let rules_url = await browser.storage.local.get("settings");
		rules_url = rules_url.settings.yara_rules_url;
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
			all_rules = await response.text();
			browser.storage.local.set({"raw_rules": all_rules});
			this.raw_yara_rules =  all_rules;
			return true;
		}
		console.log('Problem Fetching Rules!!');
		await this.get_rules_from_ls();
		return false;	
	}
	
	async get_rules_from_ls(){
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
			let matches_dict = {};
			const scan_item = scan_queue.shift();
			const content_sha256 = utils.toHexString(new sjcl.hash.sha256.hash(scan_item[1]));
			console.log(content_sha256);
			// Check if the file was already scanned, for efficiency
			if(!this.documents_scanned[content_sha256]){
				// Here the yara actually runs
				const yara_matches = this.yara_eng.run(scan_item[1], this.raw_yara_rules);
				this.documents_scanned[content_sha256] = {'is_match' : false, 'matches': {}, 'urls': []};
				if (yara_matches.compileErrors.size() > 0) {
                    for (let i = 0; i < yara_matches.compileErrors.size(); i++) {
                        const compileError = yara_matches.compileErrors.get(i);
                        if (!compileError.warning) {
                            throw new OperationError(`Error on line ${compileError.lineNumber}: ${compileError.message}`);
                    	}
                    }
                }
                console.log(yara_matches.matchedRules.size());
                for (let i = 0; i < yara_matches.matchedRules.size(); i++) {
                	let metadata = {};
                	const rule = yara_matches.matchedRules.get(i);
                	console.log(`${scan_item[0]}: ${rule.ruleName}`);
                	for (var j = 0; j < rule.metadata.size() ; j++) {
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
			this.documents_scanned[content_sha256]['urls'].push(scan_item[0])
			let url = new URL(scan_item[0]);
			let file_path = url.pathname || '';
			let filename;
			if(file_path.length < 2) {
				filename = '';
			} else {
				filename = file_path.split('/').slice(-1)[0] ||  file_path.split('/').slice(-2)[0];
			}
			const message = {
				'type': MSG_MATCH,
				'data':
				{
					'url': scan_item[0], 
					'file_name' : filename,
					'matches': this.documents_scanned[content_sha256]['matches'],
					'first_time':this.documents_scanned[content_sha256]['urls'].length == 1, 
					'sha256': content_sha256,
				}
			};
			new_message(message);
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

		let prop_name = "sample_" + sha256;
		let decoder = new TextDecoder("utf-8");
		let dict = {};
		dict[`sample_${sha256}`] = btoa(encodeURIComponent(data));
		browser.storage.local.set(dict).then(setItem, onError);
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
		data.push(decoder.decode());
		let str = data.join("");
		filter.write(encoder.encode(str));
		filter.close();
		scan_queue.push([details.url, str]);
	};
}

async function new_message(data)
{
	if (data['type'] == MSG_MATCH)
	{
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
	}
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