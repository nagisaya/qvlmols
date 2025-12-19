/**
 * Surge IP Security Check Script
 *
 * 功能概述：
 * - 偵測並顯示入口／出口 IP 資訊
 * - 評估 IP 風險等級與類型
 * - 顯示地理位置與電信業者資訊
 * - 支援網路變更自動偵測與通知
 *
 * 資料來源：
 * 𝟷 入口 IP: bilibili API (DIRECT)
 * 𝟸 出口 IP: ip.sb API
 * 𝟹 代理策略: Surge /v1/requests/recent
 * 𝟺 風險評分: IPQualityScore (主, 需 API) → ProxyCheck (備) → Scamalytics (最後)
 * 𝟻 IP 類型: IPPure API
 * 𝟼 地理資訊: ip.sb, ip-api.com API
 *
 * 參數說明：
 * - TYPE: 設為 EVENT 表示網路變更觸發（自動判斷，無需手動設定）
 * - ipqs_key: IPQualityScore API Key（可選）
 * - event_delay: 網路變更後延遲偵測（秒），預設 2 秒
 *
 * 配置範例：
 * [Panel]
 * ip-security-panel = script-name=ip-security-panel,update-interval=600
 *
 * [Script]
 * # 手動觸發（面板）
 * ip-security-panel = type=generic,timeout=10,script-path=ip-security.js,argument=ipqs_key=YOUR_API_KEY
 *
 * # 網路變更自動觸發
 * ip-security-event = type=event,event-name=network-changed,timeout=10,script-path=ip-security.js,argument=TYPE=EVENT&ipqs_key=YOUR_API_KEY&event_delay=2
 *
 * @author HotKids&Claude
 * @version 3.0.1
 * @date 2025-12-15
 */

// ==================== 全域配置 ====================
const NAME = "ip-security";
const TIMEOUT = 10000; // 超時時間（毫秒）
const STORE_KEY_LAST_EVENT = "lastNetworkInfoEvent"; // 上次網路事件記錄的儲存鍵
const STORE_KEY_LAST_POLICY = "lastProxyPolicy"; // 上次代理策略的儲存鍵

// ==================== 參數解析 ====================
let arg = {};
if (typeof $argument !== "undefined") {
  arg = Object.fromEntries($argument.split("&").map(i => i.split("=")));
}
// 從持久化儲存讀取參數（可選）
const storedArg = $persistentStore.read(NAME);
if (storedArg) {
  try {
    arg = { ...arg, ...JSON.parse(storedArg) };
  } catch (e) {}
}

// 自動判斷觸發類型
const isPanel = typeof $input !== "undefined" && $input.purpose === "panel";
const isRequest = typeof $request !== "undefined";
// 如果不是面板且不是請求，則視為網路變更觸發
if (!isPanel && !isRequest) {
  arg.TYPE = "EVENT";
}

// 提取配置參數
const IPQS_API_KEY = (arg.ipqs_key && arg.ipqs_key !== "null") ? arg.ipqs_key : "";
const EVENT_DELAY = parseFloat(arg.event_delay) || 2;
console.log("觸發類型: " + (arg.TYPE === "EVENT" ? "EVENT" : "手動"));

// ==================== 全域狀態控制 ====================
let finished = false;
/**
 * 完成腳本執行並返回結果
 * @param {Object} o - 返回物件
 */
function done(o) {
  if (finished) return;
  finished = true;
  $done(o);
}

// 超時保護
setTimeout(() => {
  done({ title: "偵測超時", content: "API 請求超時", icon: "leaf", "icon-color": "#9E9E9E" });
}, TIMEOUT);

// ==================== HTTP 請求工具 ====================
function httpJSON(url, policy) {
  return new Promise(r => {
    $httpClient.get(policy ? { url, policy } : { url }, (_, __, d) => {
      try { r(JSON.parse(d)); } catch { r(null); }
    });
  });
}

function httpRaw(url) {
  return new Promise(r => {
    $httpClient.get({ url }, (_, __, d) => r(d || null));
  });
}

function wait(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ==================== Surge API 互動 ====================
async function getPolicy() {
  return new Promise(r => {
    $httpAPI("GET", "/v1/requests/recent", null, res => {
      const hit = res?.requests
        ?.slice(0, 10)
        .find(i => /(api\.ip\.sb|ip-api\.com)/i.test(i.URL));
      r(hit?.policyName || null);
    });
  }).then(async policy => {
    if (policy) {
      console.log("找到代理策略: " + policy);
      $persistentStore.write(policy, STORE_KEY_LAST_POLICY);
      return policy;
    }
    console.log("未找到策略記錄，發送測試請求");
    await httpJSON("https://api.ip.sb/geoip");
    return new Promise(r => {
      setTimeout(() => {
        $httpAPI("GET", "/v1/requests/recent", null, res => {
          const hit = res?.requests
            ?.slice(0, 5)
            .find(i => /api\.ip\.sb/i.test(i.URL));
          if (hit?.policyName) {
            console.log("重試後找到策略: " + hit.policyName);
            $persistentStore.write(hit.policyName, STORE_KEY_LAST_POLICY);
            r(hit.policyName);
          } else {
            const lastPolicy = $persistentStore.read(STORE_KEY_LAST_POLICY);
            if (lastPolicy) {
              console.log("使用上次保存的策略: " + lastPolicy);
              r(lastPolicy);
            } else {
              console.log("無法找到任何策略資訊");
              r("Unknown");
            }
          }
        });
      }, 500);
    });
  });
}

// ==================== 資料處理工具 ====================
function flag(cc) {
  if (!cc || cc.length !== 2) return "";
  if (cc.toUpperCase() === "TW") cc = "CN"; // 臺灣地區使用中國國旗（兼容國行裝置）
  const b = 0x1f1e6;
  return String.fromCodePoint(
    b + cc.charCodeAt(0) - 65,
    b + cc.charCodeAt(1) - 65
  );
}

function riskText(s) {
  if (s <= 15) return ["極度純淨 IP", "#0D6E3D"];
  if (s <= 25) return ["純淨 IP", "#2E9F5E"];
  if (s <= 40) return ["一般 IP", "#8BC34A"];
  if (s <= 50) return ["微風險 IP", "#FFC107"];
  if (s <= 70) return ["一般風險 IP", "#FF9800"];
  return ["極度風險 IP", "#F44336"];
}

function parseScore(html) {
  const m = html?.match(/Fraud Score[^0-9]*([0-9]{1,3})/i);
  return m ? Number(m[1]) : null;
}

// ==================== 風險評分獲取（三級回落） ====================
async function getRiskScore(ip) {
  let score = null;
  let source = "";
  if (IPQS_API_KEY) {
    try {
      const ipqs = await httpJSON(
        "https://ipqualityscore.com/api/json/ip/" + IPQS_API_KEY + "/" + ip + "?strictness=1"
      );
      if (ipqs?.success && ipqs?.fraud_score !== undefined) {
        score = ipqs.fraud_score;
        source = "IPQS";
      }
    } catch (e) { console.log("IPQS 查詢失敗"); }
  }
  if (score === null) {
    try {
      const proxycheck = await httpJSON(
        "https://proxycheck.io/v2/" + ip + "?risk=1&vpn=1"
      );
      if (proxycheck?.[ip]?.risk !== undefined) {
        score = proxycheck[ip].risk;
        source = "ProxyCheck";
      }
    } catch (e) { console.log("ProxyCheck 查詢失敗"); }
  }
  if (score === null) {
    try {
      const html = await httpRaw("https://scamalytics.com/ip/" + ip);
      score = parseScore(html);
      if (score !== null) source = "Scamalytics";
    } catch (e) { console.log("Scamalytics 查詢失敗"); }
  }
  return { score: score !== null ? score : 50, source: source || "Default" };
}

function notify(title, subtitle, content) {
  if (arg.TYPE === "EVENT") {
    $notification.post(title, subtitle, content);
  }
}

// ==================== 主執行 ====================
(async () => {
  console.log("=== IP 安全檢測開始 ===");
  if (arg.TYPE === "EVENT" && EVENT_DELAY > 0) {
    console.log("等待網路穩定 " + EVENT_DELAY + " 秒");
    await wait(EVENT_DELAY * 1000);
  }
  const enter = await httpJSON("https://api.bilibili.com/x/web-interface/zone", "DIRECT");
  const inIP = enter?.data?.addr;
  const exit = await httpJSON("https://api.ip.sb/geoip");
  const outIP = exit?.ip;
  const exit6 = await Promise.race([
    httpJSON("https://api64.ip.sb/geoip"),
    new Promise(r => setTimeout(() => r(null), 1500))
  ]);
  const outIP6 = exit6?.ip;

  if (!inIP || !outIP) {
    console.log("IP 獲取失敗");
    return done({ title: "IP 獲取失敗", content: "無法獲取入口或出口 IPv4", icon: "leaf", "icon-color": "#9E9E9E" });
  }
  console.log("入口 IP: " + inIP + ", 出口 IP: " + outIP);

  if (arg.TYPE === "EVENT") {
    const lastEvent = $persistentStore.read(STORE_KEY_LAST_EVENT);
    let lastData = {};
    if (lastEvent) {
      try { lastData = JSON.parse(lastEvent); } catch {}
    }
    if (
      inIP === lastData.inIP &&
      outIP === lastData.outIP &&
      outIP6 === lastData.outIP6
    ) {
      console.log("網路資訊未變更，略過");
      return done({});
    }
    console.log("網路資訊已變更");
    $persistentStore.write(JSON.stringify({ inIP, outIP, outIP6 }), STORE_KEY_LAST_EVENT);
  }

  const policy = await getPolicy();
  const riskInfo = await getRiskScore(outIP);
  const [riskLabel, color] = riskText(riskInfo.score);
  const ippure = await httpJSON("https://my.ippure.com/v1/info");
  const ipType = ippure?.isResidential ? "住宅 IP" : "機房 IP";
  const ipSrc = ippure?.isBroadcast ? "廣播 IP" : "原生 IP";

  const [inGeo, outGeo, inISP, outISP] = await Promise.all([
    httpJSON("http://ip-api.com/json/" + inIP + "?fields=country,countryCode,regionName,city"),
    httpJSON("http://ip-api.com/json/" + outIP + "?fields=country,countryCode,regionName,city"),
    httpJSON("https://api.ip.sb/geoip/" + inIP),
    httpJSON("https://api.ip.sb/geoip/" + outIP)
  ]);

  const contentParts = [
    "IP 風控值：" + riskInfo.score + "% " + riskLabel + " (" + riskInfo.source + ")",
    "",
    "IP 類型：" + ipType + " | " + ipSrc,
    "",
    "入口 IP：" + inIP,
    "地區：" + flag(inGeo?.countryCode) + " " + [inGeo?.city, inGeo?.regionName, inGeo?.countryCode].filter(Boolean).join(", "),
    "電信業者：" + (inISP?.organization || "Unknown"),
    ""
  ];

  if (outIP6) {
    const same = outGeo?.countryCode === exit6?.country_code && outISP?.organization === exit6?.organization;
    if (same) {
      contentParts.push("出口 IP⁴：" + outIP);
      contentParts.push("出口 IP⁶：" + outIP6);
      contentParts.push("地區：" + flag(outGeo?.countryCode) + " " + [outGeo?.city, outGeo?.regionName, outGeo?.countryCode].filter(Boolean).join(", "));
      contentParts.push("電信業者：" + (outISP?.organization || "Unknown"));
    } else {
      contentParts.push("出口 IP⁴：" + outIP);
      contentParts.push("地區⁴：" + flag(outGeo?.countryCode) + " " + [outGeo?.city, outGeo?.regionName, outGeo?.countryCode].filter(Boolean).join(", "));
      contentParts.push("電信業者⁴：" + (outISP?.organization || "Unknown"));
      contentParts.push("");
      contentParts.push("出口 IP⁶：" + outIP6);
      contentParts.push("地區⁶：" + flag(exit6?.country_code) + " " + [exit6?.city, exit6?.region, exit6?.country_code].filter(Boolean).join(", "));
      contentParts.push("電信業者⁶：" + (exit6?.organization || "Unknown"));
    }
  } else {
    contentParts.push("出口 IP：" + outIP);
    contentParts.push("地區：" + flag(outGeo?.countryCode) + " " + [outGeo?.city, outGeo?.regionName, outGeo?.countryCode].filter(Boolean).join(", "));
    contentParts.push("電信業者：" + (outISP?.organization || "Unknown"));
  }

  const content = contentParts.join("\n");

  if (arg.TYPE === "EVENT") {
    const notifyTitle = "網路已切換 | " + policy;
    const notifySubtitle = "Ⓓ " + inIP + " " + outIP;
    const notifyContentParts = [
      "Ⓓ " + flag(inGeo?.countryCode) + " " + [inGeo?.city, inGeo?.country].filter(Boolean).join(", ") + " · " + (inISP?.organization || "Unknown"),
      " " + flag(outGeo?.countryCode) + " " + [outGeo?.city, outGeo?.country].filter(Boolean).join(", ") + " · " + (outISP?.organization || "Unknown"),
      " 風控：" + riskInfo.score + "% " + riskLabel + " | 類型：" + ipType + " · " + ipSrc
    ];
    notify(notifyTitle, notifySubtitle, notifyContentParts.join("\n"));
    console.log("=== 已發送通知 ===");
    done({});
  } else {
    console.log("=== 面板顯示 ===");
    done({ title: "代理策略：" + policy, content: content, icon: "leaf.fill", "icon-color": color });
  }
})();
