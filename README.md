# Yobi

***Yara Based Detection for web browsers***
Yobi is a basic firefox extension which allows to run public or private YARA rules on all scripts and pages rendered by the browser.
Yobi saves files that trigger its rules and allows further inspection of them.

Yobi is completly serverless - no telemtry or other information is collected.

## System Requirements

## Installation

Yobi has been submitted to Mozilla for verification, as soo as they sign it I will put here the link to the add-on installation

### Manual Installation

1.clone the repo.
2. Go to `about:debugging` in firefox or other Gecko based browser, click "This Firefox"-> Load Temporary Add on and select manifest.json.
3. Done!

## YARA rules

YARA rules are fetched from a repository of JS rules I created: [js-yara-rules](https://github.com/imp0rtp3/js-yara-rules/). The repo consists of free JS rules I found on the internet and some I wrote myself. Feel free to create pull requests for additional rellevant rules. 
The repository can be changed in `config.py`

You can change the yara rules the extension runs under Add-ons->Yobi->Preferences

## Yobi's Inner Workings

### Dependencies
Yobi Depends on the following libraries:
1. [libyara-wasm](https://github.com/mattnotmitt/libyara-wasm) - A porting of the whole YARA engine to wasm
2. [SJCL](https://github.com/bitwiseshiftleft/sjcl) - JS encryption library used for calculating sha256.
3. [jszip](https://github.com/Stuk/jszip) - A compact JS library to create zip files. used [PR 6969](https://github.com/Stuk/jszip/pull/696) that added the option to encrypt the archive.
4. Bootstrap
5. jQuery

### Execution Flow

Yobi uses the Gecko `webrequests` feature `browser.webRequest.onBeforeRequest` which enables it to intercept any request and response. Yobi saves the buffer and forward it. The YARA rules run asynchronously to that and alert whether a match is found.

### Why doesn't Yobi block the malicious scripts?

Preventing any script to run before running YARA rules on it would create a significant delay for the user.= 

## Continuing Development

This version is still very basic and should serve as a prototype only. Please open issues and pull request for new features or bugs you encounter.

## Contact and Feedback

Contact me via twitter - [@imp0rtp3](https://twitter.com/imp0rtp3/)

## Screenshots

![Yobi alerts Dashboard](https://raw.githubusercontent.com/imp0rtp3/Yobi/main/imgs/scr1.png)
