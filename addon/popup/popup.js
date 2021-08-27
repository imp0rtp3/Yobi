function setClipboard(text) {
    navigator.clipboard.writeText(text);
}

class MatchesUpdater{
	
	constructor(){
		let that = this
		this.current_matches_len = 0;
		browser.storage.local.get("rule_matches", items => this.storage_listener(items));
		this.storage_change_listener = browser.storage.onChanged.addListener(
			function(c,a){
				that.browser_storage_change(c,a, that);
			}
		);
		$(window).on("beforeunload", function(){
			browser.storage.onChanged.removeListener(this.storage_change_listener);
		});
		$('#trash_icon').on('click', function(e){
			browser.storage.local.set({"rule_matches": []});
		});
	};

	storage_listener (item) {
		var matches = item['rule_matches'];
		if (matches){
			this.current_matches_len = matches.length;
			this.add_rule_matches(matches);
		}
	};
	onErrorStorage(error) {
		console.log(`[***] Error: ${error}`);
	};

	browser_storage_change(changes, areaName, self) {
		if(areaName != "local" || !changes["rule_matches"])
		{
			return;
		}
		var old_len = self.current_matches_len;
		self.current_matches_len = changes["rule_matches"].newValue.length;
		if(self.current_matches_len == 0)
			self.remove_matches();
		self.add_rule_matches(changes["rule_matches"].newValue.slice(old_len));
	};

	remove_matches(){
		$("#no-hits").toggle();
		$("#hits").toggle();
		$("#hits").empty();
		browser.browserAction.setIcon({path: "../icons/emoji-laughing.svg"});

	};

	add_rule_matches(matches) {
		$("#no-hits").css({"display": "none"});
		$("#hits").css({"display": "block"});
		for (var i = 0; i < matches.length; i++) {
			var $sig_block = $("<div>", {id: "list-profile-list", class: ""});
			var $link = $("<a>", {class: "list-group-item-danger hit_item list-group-item"});
			var $desc = $("<div>", {id: "description", class:"description"});
			var $cp_img = $('<img>', {class:"copy_icon", id: "copy_icon", src:"../icons/copy.png"});
			var url = new URL(matches[i].url);
			var host = url.host;
			var file_path = url.pathname || '';
			if(file_path.length < 2)
				$link.html(`<b><h3>${host}</h3></b>`);
			else 
			{
				file_path = file_path.split('/').slice(-1)[0] ||  file_path.split('/').slice(-2)[0];
				$link.html(`<b><h3>${host}</h3></b> - <i>${file_path}</i>`);
			}
			var desc_html = `<b>Matches:</b>${Object.keys(matches[i].matches).join(', ')}<br>
			<b>Filepath: </b><div id="filepath_${matches[i].sha256}">${matches[i].filepath}</div><br>
			<b>Password: </b><div id="password_${matches[i].sha256}">${matches[i].password}</div>`;
			desc_html += `<a href="https://www.virustotal.com/gui/file/${matches[i].sha256}" role="button" class="vt_button btn btn-primary" >Check In VT</a>`;
			$desc.html(desc_html);
			$link.on('click', function (e) {
				 e.preventDefault();
				 $(this).parent().children('#description').eq(0).toggle();
			});
			$sig_block.append($link);
			$sig_block.append($desc);
			$("#hits").append($sig_block);
			$cp_img.clone().appendTo(`#filepath_${matches[i].sha256}`).on('click', function(e) {setClipboard($(this).parent().text());});
			$cp_img.clone().appendTo(`#password_${matches[i].sha256}`).on('click', function(e) {setClipboard($(this).parent().text());});
		}
	};
}

let MU = new MatchesUpdater();





