const DEF_MAL_NAME = "sample";


function setClipboard(text) {
    navigator.clipboard.writeText(text);
}

class MatchesUpdater{

	constructor(){
		let that = this;
		this.matches_dict = {};
		browser.storage.local.get("rule_matches", items => this.storage_listener(items));
		this.storage_change_listener = browser.storage.onChanged.addListener(
			function(c,a){
				that.browser_storage_change(c,a);
			}
		);
		$(window).on("beforeunload", function(){
			browser.storage.onChanged.removeListener(this.storage_change_listener);
		});
		$('#trash_icon').on('click', function(e){
			browser.storage.local.set({"rule_matches": {}});
		});
	};

	storage_listener (item) {
		var matches = item['rule_matches'];
		if (Object.keys(matches).length){
			this.matches_dict = item["rule_matches"];
			this.add_rule_matches(matches);
		}
	};
	onErrorStorage(error) {
		console.log(`[***] Error: ${error}`);
	};

	browser_storage_change(changes, areaName) {
		if(areaName != "local" || !changes["rule_matches"])	{
			return;
		}
		if(Object.keys(changes["rule_matches"].newValue).length == 0) {
			this.remove_matches();
			return;
		}
		let new_vals = {}
		for(key in changes["rule_matches"].newValue) {
			if(!changes["rule_matches"].oldValye[key])
				new_vals[key] = changes["rule_matches"].newValue[key];
		}
		this.add_rule_matches(new_vals);
	};

	remove_matches(){
		$("#no-hits").show();
		$("#hits").hide();
		$("#hits").empty();
		$(".hits_title").hide();
		this.matches_dict = {};
		browser.browserAction.setIcon({path: "../icons/emoji-laughing.svg"});
	};

	add_rule_matches(matches) {
		let self = this;
		$("#no-hits").hide();
		$("#hits").show();
		$(".hits_title").show();
		for (const sha256 in matches) {
			var $sig_block = $("<div>", {id: "list-profile-list", class: ""});
			var $link = $("<a>", {class: "w3-theme-d5 hit_item w3-hover-theme w3-hover-border-theme list-group-item"});
			var $desc = $("<div>", {id: "description", class:"w3-theme-l5 w3-text-theme description"});
			var $cp_img = $('<img>', {class:"copy_icon", id: "copy_icon", src:"../icons/copy.png"});
			var url = new URL(matches[sha256].url);
			var host = url.host;
			if(!matches[sha256].file_name)
				$link.html(`<b><h3>${host}</h3></b>`);
			else 
			{
				$link.html(`<b><h3>${host}</h3></b> - <i>${matches[sha256].file_name}</i>`);
			}
			console.log(matches[sha256]);
			var desc_html = `<b>Matches: </b>${Object.keys(matches[sha256].matches).join(', ')}<br>
			<b>Sha256: </b><div id="hash_${sha256}">${sha256}</div>`;
			desc_html += `<a href="https://www.virustotal.com/gui/file/${sha256}" role="button" class="w3-hover-text-theme w3-theme-l1 desc_button btn" >VT</a>`;
			desc_html += `<button type="button" id="download_sample${sha256}" class="w3-hover-text-theme w3-theme-l1 desc_button download_button btn">Sample</button>`;
			desc_html += `<button type="button" id="download_details${sha256}" style="float: right;" class="w3-hover-text-theme w3-theme-l1 desc_button download_button btn">Details</button>`;
			$desc.html(desc_html);
			$link.on('click', function (e) {
				 e.preventDefault();
				 $(this).parent().children('#description').eq(0).toggle();
			});
			$sig_block.append($link);
			$sig_block.append($desc);
			$("#hits").append($sig_block);
			$cp_img.clone().appendTo(`#hash_${sha256}`).on('click', function(e)
			{
				 	setClipboard($(this).parent().text());
			});
			$(`#download_sample${sha256}`).on('click', function (e)
			{
				self.download_sample(sha256);
			});
			$(`#download_details${sha256}`).on('click', function (e)
			{
				const blob = new Blob([JSON.stringify(self.matches_dict[sha256], null, 4)], {type : 'application/json'});
				const download_url = URL.createObjectURL(blob);
				browser.downloads.download({url: download_url, filename: `${sha256}.json`});
			});
		}
	};

	download_sample(sha256)
	{
		const var_name = 'sample_' + sha256;
		let self = this;
		browser.storage.local.get(var_name).then(item => this.gotFile(item) , self.onError);
	}
	
	async gotFile (item){
		const sha256 = Object.keys(item)[0].slice(-64); // Take out the "sample_"
		const obj = decodeURIComponent(atob(Object.values(item)[0]));
		let encoder = new TextEncoder();
		const filename = (this.matches_dict[sha256].file_name || DEF_MAL_NAME) + ".dnr";
		const zip_pass = (await browser.storage.local.get("settings")).settings.archive_password;

		await $.getScript("../jszip_pr696.min.js");
		var zip = new JSZip();
		zip.file(filename, encoder.encode(obj));
		zip.generateAsync({type:"blob", password: zip_pass , encryptStrength: 3,}).then(
		function(content) {
			const blob = new Blob([content], {type : 'application/zip'});
			const download_url = URL.createObjectURL(blob);
			browser.downloads.download({url: download_url, filename: `${sha256}.zip`});
		});
	}

	onError(e){
		console.log(`Error retrieving File: ${e}`);
	}
}

let MU = new MatchesUpdater();






