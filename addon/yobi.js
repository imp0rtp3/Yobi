

q = [];
const MSG_MATCH = 1;
const MSG_ERROR = 2;
const PORT = 8392;
let socket = 0;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
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
		var msg = {};
		msg[details.url]= str;
		q.push(JSON.stringify(msg));
	};
}

async function init_ws() {
	var success = false;
	while(!success)
	{
		try
		{
			socket = new WebSocket(`wss://127.0.0.1:${PORT}`);
			success = true;
		}
		catch (e){
			await sleep(1000);
		}
	}
	socket.onclose = function (event) {
		init_ws();
	}
	socket.onopen = function(event) {
		browser.notifications.create({
				"type": "basic",
				"iconUrl": browser.runtime.getURL("icons/emoji-laughing.svg"),
				"title": "Connected to the Yarascanner!",
				"message": ""
		});
	}
	setInterval(send_msgs, 100);
	socket.onmessage = function(event) {
		var data = JSON.parse(event.data);
		if (data['type'] == MSG_MATCH)
		{
			// Change the icon in the toolbar to the icon indicating suspisious script
			browser.browserAction.setIcon({path: "icons/emoji-frown-fill.svg"});
			browser.notifications.create({
				"type": "basic",
				"iconUrl": browser.runtime.getURL("icons/virus.png"),
				"title": "Found Suspicious File!",
				"message": `Found ${Object.keys(data.data.matches).toString()} in ${data.data.url.replace('://','[:]//')}`
			});

			// Update the rule_matches browser localstorage for the popup
			browser.storage.local.get("rule_matches", function(items)
			{
					var rm = items['rule_matches'];
					if(!rm)
						rm = [];
					browser.storage.local.set({"rule_matches": rm.concat(data.data)});		
			});
		}
	};
}

function send_msgs(){
	while (q.length>0) {
		content = q.shift()
		socket.send(content)
	}
}

init_ws();
browser.webRequest.onBeforeRequest.addListener(
	listener,	
	{"urls":["<all_urls>"], "types": ["main_frame", "script", "object", "sub_frame", "other"]},
	["blocking"]);
