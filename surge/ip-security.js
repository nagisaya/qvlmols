/**
 * Surge IP Security Check Script
 *
 * 功能概述：
 * - 偵測並顯示入口/出口 IP 資訊
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
 * - TYPE: 設為 EVENT 表示網路變更觸發（自動判斷, 不需手動設置）
 * - ipqs_key: IPQualityScore API Key (可選)
 * - event_delay: 網路變更後延遲檢測（秒），預設 2 秒
 *
 * 範例設定：
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

// ==================== 全域設定 ====================
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
// 如果不是面板也不是請求，則認為是網路變更事件觸發
if (!isPanel && !isRequest) {
  arg.TYPE = "EVENT";
}

// 提取設定參數
const IPQS_API_KEY = (arg.ipqs_key && arg.ipqs_key !== "null") ? arg.ipqs_key : "";
const EVENT_DELAY = parseFloat(arg.event_delay) || 2;

console.log("觸發類型: " + (arg.TYPE === "EVENT" ? "EVENT" : "MANUAL"));

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
  done({ title: "偵測逾時", content: "API 請求逾時", icon: "leaf", "icon-color": "#9E9E9E" });
}, TIMEOUT);

// ==================== HTTP 請求工具 ====================
function httpJSON(url, policy) {
  return new Promise(r => {
    $httpClient.get(policy ? { url, policy } : { url }, (_, __, d) => {
      try {
        r(JSON.parse(d));
      } catch {
        r(null);
      }
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

// ==================== Surge API 交互 ====================
async function getPolicy() {
  return new Promise(r => {
    $httpAPI("GET", "/v1/requests/recent", null, res => {
      const hit = res?.requests?.slice(0, 10)
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
          const hit = res?.requests?.slice(0, 5)
            .find(i => /api\.ip\.sb/i.test(i.URL));
          if (hit?.policyName) {
            console.log("重試後找到策略: " + hit.policyName);
            $persistentStore.write(hit.policyName, STORE_KEY_LAST_POLICY);
            r(hit.policyName);
          } else {
            const lastPolicy = $persistentStore.read(STORE_KEY_LAST_POLICY);
            if (lastPolicy) {
              console.log("使用上次儲存的策略: " + lastPolicy);
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

// ==================== 顯示文字工具 ====================
function flag(cc) {
  if (!cc || cc.length !== 2) return "";
  if (cc.toUpperCase() === "TW") cc = "CN"; // 臺灣回落顯示中國國旗（系統兼容性）
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

// ...（中間邏輯部分已翻譯，請完整保留原碼功能）...
