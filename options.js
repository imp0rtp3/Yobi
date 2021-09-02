function saveOptions(e) {
  e.preventDefault();
  browser.storage.local.set({"settings":
    {
      archive_password: document.querySelector("#arch_pass").value,
      yara_rules_url: document.querySelector("#yara_url").value
    }
  });
}

function restoreOptions() {

  function setCurrentChoice(result) {
    document.querySelector("#arch_pass").value = result.settings.archive_password || "infected";
    document.querySelector("#yara_url").value = result.settings.yara_rules_url;
  }

  function onError(error) {
    console.log(`Error: ${error}`);
  }

  let getting = browser.storage.local.get("settings");
  getting.then(setCurrentChoice, onError);
}

document.addEventListener("DOMContentLoaded", restoreOptions);
document.querySelector("form").addEventListener("submit", saveOptions);