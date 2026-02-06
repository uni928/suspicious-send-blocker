// background.js
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "blocked") {
    // ここで通知を出したり、将来的にDNRルール自動生成も可能
    // console.log("Blocked:", msg.payload);
  }
});
