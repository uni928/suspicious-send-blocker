// heuristics.js
(() => {
  const DEFAULTS = {
    // そのページのドメイン以外への送信を疑う（ホワイトリストで緩和）
    blockCrossOriginPost: true,

    // よくある「秘匿情報っぽいキー」を含むなら疑う
    suspiciousKeys: ["password", "passwd", "pwd", "token", "auth", "session", "cookie", "credit", "card", "cvv"],

    // 送信サイズが大きすぎるなら疑う（雑な外部送信対策）
    maxBodyBytes: 200_000,

    // ホワイトリスト（ユーザーが後で追加）
    allowHosts: []
  };

  function tryParseUrl(url, base) {
    try { return new URL(url, base); } catch { return null; }
  }

  function estimateBytes(x) {
    try {
      if (typeof x === "string") return new Blob([x]).size;
      if (x instanceof FormData) {
        // 厳密でなくてOK。キー＋値の文字列化で概算
        let s = "";
        for (const [k, v] of x.entries()) s += `${k}=${String(v)}&`;
        return new Blob([s]).size;
      }
      if (x instanceof URLSearchParams) return new Blob([x.toString()]).size;
      if (x && typeof x === "object") return new Blob([JSON.stringify(x)]).size;
      return 0;
    } catch { return 0; }
  }

  function extractKeys(body) {
    const keys = new Set();
    try {
      if (body instanceof FormData) {
        for (const [k] of body.entries()) keys.add(String(k).toLowerCase());
      } else if (body instanceof URLSearchParams) {
        for (const [k] of body.entries()) keys.add(String(k).toLowerCase());
      } else if (typeof body === "string") {
        // JSONっぽければキー抽出
        const t = body.trim();
        if (t.startsWith("{") && t.endsWith("}")) {
          const o = JSON.parse(t);
          if (o && typeof o === "object") Object.keys(o).forEach(k => keys.add(k.toLowerCase()));
        }
      } else if (body && typeof body === "object") {
        Object.keys(body).forEach(k => keys.add(k.toLowerCase()));
      }
    } catch {}
    return keys;
  }

  async function loadConfig() {
    const { config } = await chrome.storage.sync.get({ config: DEFAULTS });
    return { ...DEFAULTS, ...(config || {}) };
  }

  // 判定本体：trueならブロック推奨
  window.__SSB__ = {
    loadConfig,
    async isSuspicious({ url, method, body, initiator }) {
      const cfg = await loadConfig();

      const u = tryParseUrl(url, initiator || location.href);
      if (!u) return { block: false, reason: "invalid_url" };

      const host = u.host.toLowerCase();
      if (cfg.allowHosts.map(h => h.toLowerCase()).includes(host)) {
        return { block: false, reason: "allowlisted" };
      }

      const m = (method || "GET").toUpperCase();
      const sameOrigin = (u.origin === location.origin);

      // クロスオリジンPOSTを止める（まずはここが強い）
      if (cfg.blockCrossOriginPost && !sameOrigin && ["POST", "PUT", "PATCH", "DELETE"].includes(m)) {
        return { block: true, reason: "cross_origin_write", details: { origin: u.origin } };
      }

      const bytes = estimateBytes(body);
      if (bytes > cfg.maxBodyBytes) {
        return { block: true, reason: "body_too_large", details: { bytes } };
      }

      const keys = extractKeys(body);
      for (const k of cfg.suspiciousKeys) {
        if (keys.has(k)) {
          // キーが含まれる送信を外部に飛ばすのは特に危険
          if (!sameOrigin && ["POST", "PUT", "PATCH", "DELETE"].includes(m)) {
            return { block: true, reason: "suspicious_keys_external", details: { key: k } };
          }
        }
      }

      return { block: false, reason: "ok" };
    }
  };
})();
