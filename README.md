# Yobi

<img align="right" src="https://raw.githubusercontent.com/imp0rtp3/Yobi/main/icons/icon128.png" alt="drawing" width="200"/>

[<h2>Install Yobi Here</h2>](https://addons.mozilla.org/en-US/firefox/addon/yobi/)

***Yara Based Detection for web browsers***

Yobi is a basic firefox extension which allows to run public or private YARA rules on all scripts and pages rendered by the browser.
Yobi saves files that trigger its rules and allows further inspection of them.

Yobi is completly serverless - no telemtry or other information is collected.

## Manual Installation

1. clone the repo.
2. Go to `about:debugging` in firefox or other Gecko based browser, click "This Firefox"-> Load Temporary Add on and select manifest.json.
3. Done!

## What can Yobi do?

1. Capture any file requested by the web browser and identified as malicious by a YARA rule.
2. Use custom YARA rules.
3. Download the malicious files   (as zip, default password is "infected").
4. Query the file hash in VirusTotal.


## YARA rules

YARA rules are fetched from a repository of JS rules I created: [js-yara-rules](https://github.com/imp0rtp3/js-yara-rules/). The repo consists of free JS rules I found on the internet and some I wrote myself. Feel free to create pull requests for additional rellevant rules. 

You can change the yara rules the extension uses under Add-ons->Yobi->Preferences

Right now, YARA version 4.0.5 is used. libyara-wasm will be updated shortly and Yobi will then run the latest YARA verions.

## Yobi's Inner Workings

### Execution Flow

Yobi uses the Gecko `webrequests` feature `browser.webRequest.onBeforeRequest` which enables it to intercept any request and response. Yobi saves the buffer and forward it. The YARA rules run asynchronously to that and alert whether a match is found.


### Dependencies
Yobi Depends on the following libraries:
1. [libyara-wasm](https://github.com/mattnotmitt/libyara-wasm) - A porting of the whole YARA engine to wasm
2. [SJCL](https://github.com/bitwiseshiftleft/sjcl) - JS encryption library used for calculating sha256.
3. [jszip](https://github.com/Stuk/jszip) - A compact JS library to create zip files. used [PR 6969](https://github.com/Stuk/jszip/pull/696) that added the option to encrypt the archive.
4. Bootstrap
5. jQuery

### Why doesn't Yobi block the malicious scripts?

Preventing any script to run before running YARA rules on it would create a significant delay for the user.= 

## Continuing Development

This version is still very basic and should serve as a prototype only. Please open issues and pull request for new features or bugs you encounter.

## Contact and Feedback

Contact me via twitter - [@imp0rtp3](https://twitter.com/imp0rtp3/)

## Screenshots

![Yobi alerts Dashboard Closed](https://raw.githubusercontent.com/imp0rtp3/Yobi/main/screens/scr1.png)

![Yobi alerts Dashboard Opened](https://raw.githubusercontent.com/imp0rtp3/Yobi/main/screens/scr2.png)
