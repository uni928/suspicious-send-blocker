// content.js
(() => {
  const log = async (entry) => {
    const { history } = await chrome.storage.local.get({ history: [] });
    history.unshift({ ...entry, ts: Date.now(), page: location.href });
    history.splice(0, 200);
    await chrome.storage.local.set({ history });
  };

  const blockAndNotify = async ({ kind, url, method, reason, details }) => {
    await log({ kind, url, method, reason, details });
    chrome.runtime.sendMessage({ type: "blocked", payload: { kind, url, method, reason, details } }).catch(() => {});
  };

  // 1) フォーム送信（ユーザー操作の submit を止める）
  document.addEventListener("submit", async (e) => {
    try {
      const form = e.target;
      if (!(form instanceof HTMLFormElement)) return;

      const action = form.getAttribute("action") || location.href;
      const method = (form.getAttribute("method") || "GET").toUpperCase();

      const body = new FormData(form);
      const res = await window.__SSB__.isSuspicious({ url: action, method, body, initiator: location.href });

      if (res.block) {
        e.preventDefault();
        e.stopImmediatePropagation();
        await blockAndNotify({ kind: "form_submit", url: action, method, reason: res.reason, details: res.details });
        alert(`送信をブロックしました\n理由: ${res.reason}\n宛先: ${action}`);
      }
    } catch {}
  }, true);

  // 2) form.submit() の直呼びも止める（イベントを通らないケース対策）
  const origSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function () {
    // submit() は同期APIなので、ここは「安全側」で一旦止めてユーザーに確認…など設計が必要。
    // 簡易版ではイベント経由を主にし、ここはログだけにするのも手。
    try {
      const action = this.getAttribute("action") || location.href;
      const method = (this.getAttribute("method") || "GET").toUpperCase();
      // ここで同期ブロックは難しいため、まずは警告ログ（強化版でモーダル同期確認などに）
      chrome.runtime.sendMessage({ type: "formSubmitCalled", payload: { action, method } }).catch(() => {});
    } catch {}
    return origSubmit.apply(this, arguments);
  };

  // 3) fetch フック
  const origFetch = window.fetch;
  window.fetch = async function (input, init = {}) {
    const url = (typeof input === "string") ? input : (input && input.url);
    const method = (init.method || (input && input.method) || "GET").toUpperCase();
    const body = init.body;

    const res = await window.__SSB__.isSuspicious({ url, method, body, initiator: location.href });
    if (res.block) {
      await blockAndNotify({ kind: "fetch", url, method, reason: res.reason, details: res.details });
      // 送信キャンセル（例外で止める）
      throw new Error(`Blocked by Suspicious Send Blocker: ${res.reason}`);
    }
    return origFetch.apply(this, arguments);
  };

  // 4) XHR フック
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url) {
    this.__ssb = { method: String(method || "GET").toUpperCase(), url: String(url) };
    return origOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function (body) {
    const meta = this.__ssb || { method: "GET", url: "" };
    const proceed = async () => {
      const res = await window.__SSB__.isSuspicious({ url: meta.url, method: meta.method, body, initiator: location.href });
      if (res.block) {
        await blockAndNotify({ kind: "xhr", url: meta.url, method: meta.method, reason: res.reason, details: res.details });
        // 送信を止める：abortして例外
        try { this.abort(); } catch {}
        throw new Error(`Blocked XHR: ${res.reason}`);
      }
      return origSend.apply(this, arguments);
    };
    // sendは同期返りが前提だが、多くのサイトは例外でも止まる。ここは簡易実装。
    // より堅牢にするなら「常に非同期XHRのみ対象」等の制限を入れる。
    return proceed();
  };

  // 5) sendBeacon フック（戻り値falseでキャンセル可能）
  const origBeacon = navigator.sendBeacon?.bind(navigator);
  if (origBeacon) {
    navigator.sendBeacon = function (url, data) {
      // sendBeacon は同期なので、簡易版では「怪しければ止める」だけを同期判定で実施（軽いルールに限定推奨）
      // 今回は cross-origin write など軽い条件のみで止めるために、設定を取得せず簡易判定に寄せるのもアリ。
      // ここでは例として「クロスオリジンは止める」を即時判定。
      try {
        const u = new URL(url, location.href);
        if (u.origin !== location.origin) {
          blockAndNotify({ kind: "beacon", url, method: "POST", reason: "cross_origin_beacon", details: { origin: u.origin } });
          return false;
        }
      } catch {}
      return origBeacon.apply(this, arguments);
    };
  }
})();
