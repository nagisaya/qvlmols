/**
 * Surge IP Security Check Script
 *
 * 功能概述：
 * - 檢測並顯示入口／出口 IP 資訊
 * - 評估 IP 風險等級與類型
 * - 顯示地理位置與電信商資訊
 * - 支援網路變更自動偵測與通知
 *
 * 資料來源：
 * ① 入口 IP：bilibili API (DIRECT)
 * ② 出口 IP：ip.sb API (IPv4／IPv6)
 * ③ 代理策略：Surge /v1/requests/recent
 * ④ 風險評分：IPQualityScore（主，需 API）→ ProxyCheck（備）→ Scamalytics（兜底）
 * ⑤ IP 類型：IPPure API
 * ⑥ 地理／電信商：lang=en → ipinfo.io + ip.sb | lang=zh → bilibili（中文，ip.sb 兜底）
 *
 * 參數說明：
 * - TYPE：設為 EVENT 表示網路變更觸發（自動判斷，無需手動設定）
 * - ipqs_key：IPQualityScore API Key（可選）
 * - lang：地理資訊語言，en（預設）＝英文（ipinfo.io），zh＝中文（bilibili）
 * - event_delay：網路變更後延遲檢測（秒），預設 2 秒
 *
 * 設定範例：
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
 * @version 4.0.0
 * @date 2026-02-09
 */

// ==================== 全域設定 ====================
const CONFIG = {
  name: "ip-security",
  timeout: 10000,
  storeKeys: {
    lastEvent: "lastNetworkInfoEvent",
    lastPolicy: "lastProxyPolicy",
    riskCache: "riskScoreCache"
  },
  urls: {
    inboundIP: "https://api.bilibili.com/x/web-interface/zone",
    outboundIP: "https://api-ipv4.ip.sb/geoip",
    outboundIPv6: "https://api-ipv6.ip.sb/geoip",
    ipType: "https://my.ippure.com/v1/info",
    ipTypeCard: "https://my.ippure.com/v1/card",
    inboundInfo: (ip) => `https://api.ip.sb/geoip/${ip}`,
    biliGeo: (ip) => `https://api.live.bilibili.com/ip_service/v1/ip_service/get_ip_addr?ip=${ip}`,
    ipInfo: (ip) => `https://ipinfo.io/${ip}/json`,
    ipqs: (key, ip) => `https://ipqualityscore.com/api/json/ip/${key}/${ip}?strictness=1`,
    proxyCheck: (ip) => `https://proxycheck.io/v2/${ip}?risk=1&vpn=1`,
    scamalytics: (ip) => `https://scamalytics.com/ip/${ip}`
  },
  ipv6Timeout: 3000,
  policyRetryDelay: 500,
  riskLevels: [
    { max: 15, label: "極度純淨 IP", color: "#0D6E3D" },
    { max: 25, label: "純淨 IP",     color: "#2E9F5E" },
    { max: 40, label: "一般 IP",     color: "#8BC34A" },
    { max: 50, label: "微風險 IP",   color: "#FFC107" },
    { max: 70, label: "一般風險 IP", color: "#FF9800" },
    { max: 100, label: "極度風險 IP", color: "#F44336" }
  ]
};

// ==================== 參數解析 ====================
function parseArguments() {
  let arg = {};

  if (typeof $argument !== "undefined") {
    arg = Object.fromEntries($argument.split("&").map(i => {
      const idx = i.indexOf("=");
      return idx === -1 ? [i, ""] : [i.slice(0, idx), i.slice(idx + 1)];
    }));
  }

  const storedArg = $persistentStore.read(CONFIG.name);
  if (storedArg) {
    try { arg = { ...arg, ...JSON.parse(storedArg) }; } catch (e) {}
  }

  const isPanel = typeof $input !== "undefined" && $input.purpose === "panel";
  const isRequest = typeof $request !== "undefined";
  if (!isPanel && !isRequest) {
    arg.TYPE = "EVENT";
  }

  return {
    isEvent: arg.TYPE === "EVENT",
    ipqsKey: (arg.ipqs_key && arg.ipqs_key !== "null") ? arg.ipqs_key : "",
    lang: (arg.lang && arg.lang !== "null") ? arg.lang : "en",
    maskIP: arg.mask_ip === "1" || arg.mask_ip === "true",
    eventDelay: parseFloat(arg.event_delay) || 2
  };
}

const args = parseArguments();
console.log("觸發類型: " + (args.isEvent ? "EVENT" : "MANUAL") + ", 語言: " + args.lang);

// ==================== 全域狀態控制 ====================
let finished = false;

function done(o) {
  if (finished) return;
  finished = true;
  $done(o);
}

setTimeout(() => {
  done({ title: "檢測逾時", content: "API 請求逾時", icon: "leaf", "icon-color": "#9E9E9E" });
}, CONFIG.timeout);

// ==================== HTTP 工具 ====================
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

function surgeAPI(method, path) {
  return new Promise(r => {
    $httpAPI(method, path, null, res => r(res));
  });
}

// ==================== 資料處理工具 ====================
/**
 * 將國家代碼轉換為國旗 emoji
 */
function flag(cc) {
  if (!cc || cc.length !== 2) return "";
  if (cc.toUpperCase() === "TW") cc = "CN";
  const b = 0x1f1e6;
  return String.fromCodePoint(b + cc.charCodeAt(0) - 65, b + cc.charCodeAt(1) - 65);
}

/**
 * 根據風險分數回傳對應的描述與顏色
 */
function riskText(score) {
  const level = CONFIG.riskLevels.find(l => score <= l.max) || CONFIG.riskLevels.at(-1);
  return { label: level.label, color: level.color };
}

/**
 * IP 打碼：保留首尾段，中間用 * 取代
 * IPv4: 123.45.67.89 → 123.*.*.89
 * IPv6: 2001:db8:85a3::7334 → 2001:*:*:7334
 */
function maskIP(ip) {
  if (!ip) return ip;
  if (ip.includes(":")) {
    // IPv6
    const parts = ip.split(":");
    if (parts.length <= 2) return ip;
    return parts[0] + ":" + parts.slice(1, -1).map(() => "*").join(":") + ":" + parts.at(-1);
  }
  // IPv4
  const parts = ip.split(".");
  if (parts.length !== 4) return ip;
  return parts[0] + ".*.*." + parts[3];
}

/**
 * 格式化地理位置文字：🇺🇸 + 自訂部分
 * 面板用法：formatGeo(country_code, city, region, country_code) → 🇺🇸 City, Region, US
 * 通知用法：formatGeo(country_code, city, country_name) → 🇺🇸 City, United States
 */
function formatGeo(countryCode, ...parts) {
  return flag(countryCode) + " " + parts.filter(Boolean).join(", ");
}

/**
 * 將 ip.sb 回傳欄位正規化為內部格式
 */
function normalizeIpSb(data) {
  if (!data) return null;
  return {
    country_code: data.country_code,
    country_name: data.country,
    city: data.city,
    region: data.region,
    org: data.organization
  };
}

/**
 * 將 ipinfo.io 回傳欄位正規化為內部格式
 * ipinfo.io: { country:"US", city, region, org:"AS15169 Google LLC" }
 */
function normalizeIpInfo(data) {
  if (!data || !data.country) return null;
  return {
    country_code: data.country,
    country_name: data.country,
    city: data.city,
    region: data.region,
    org: data.org ? data.org.replace(/^AS\d+\s*/, "") : ""
  };
}

/**
 * 將 bilibili zone API 回傳欄位正規化為內部格式（中文）
 * bilibili: { code:0, data:{ addr, country:"中國", province:"香港", city:"", isp:"資料中心" } }
 * 注意：bilibili 不回傳 ISO country_code，需從 ip.sb 補齊
 */
function normalizeBilibili(data) {
  const d = data?.data;
  if (!d || !d.country) return null;
  let isp = d.isp || "";
  if (/^(移動|聯通|電信|廣電)$/.test(isp)) isp = "中國" + isp;
  return {
    country_code: null,
    country_name: d.country,
    city: d.city || "",
    region: d.province,
    org: isp
  };
}

/**
 * 從 Scamalytics HTML 中解析風險分數
 */
function parseScamalyticsScore(html) {
  const m = html?.match(/Fraud Score[^0-9]*([0-9]{1,3})/i);
  return m ? Number(m[1]) : null;
}

// ==================== 代理策略取得 ====================
/**
 * 從 Surge 最近請求中尋找符合的代理策略
 */
async function findPolicyInRecent(pattern, limit) {
  const res = await surgeAPI("GET", "/v1/requests/recent");
  const hit = res?.requests?.slice(0, limit).find(i => pattern.test(i.URL));
  return hit?.policyName || null;
}

/**
 * 取得實際使用的代理策略（含重試與回落）
 */
async function getPolicy() {
  // 第一次搜尋
  let policy = await findPolicyInRecent(/(api(-ipv4)?\.ip\.sb|ipinfo\.io)/i, 10);
  if (policy) {
    console.log("找到代理策略: " + policy);
    $persistentStore.write(policy, CONFIG.storeKeys.lastPolicy);
    return policy;
  }

  // fetchIPs 階段已送出 outboundIP 請求，等待後再重試
  console.log("未找到策略紀錄，等待後重試");
  await wait(CONFIG.policyRetryDelay);

  policy = await findPolicyInRecent(/(api(-ipv4)?\.ip\.sb|ipinfo\.io)/i, 5);
  if (policy) {
    console.log("重試後找到策略: " + policy);
    $persistentStore.write(policy, CONFIG.storeKeys.lastPolicy);
    return policy;
  }

  // 回落到上次儲存的策略
  const lastPolicy = $persistentStore.read(CONFIG.storeKeys.lastPolicy);
  if (lastPolicy) {
    console.log("使用上次儲存的策略: " + lastPolicy);
    return lastPolicy;
  }

  console.log("無法找到任何策略資訊");
  return "Unknown";
}

// ==================== 風險評分取得（三級回落） ====================
/**
 * 取得 IP 風險分數
 * 優先順序：IPQualityScore → ProxyCheck → Scamalytics
 */
async function getRiskScore(ip) {
  // 0. 檢查快取：IP 未變則直接回傳
  const cached = $persistentStore.read(CONFIG.storeKeys.riskCache);
  if (cached) {
    try {
      const c = JSON.parse(cached);
      if (c.ip === ip) {
        console.log("風險評分命中快取: " + c.score + "% (" + c.source + ")");
        return { score: c.score, source: c.source };
      }
    } catch (e) {}
  }

  function saveAndReturn(score, source) {
    $persistentStore.write(JSON.stringify({ ip, score, source }), CONFIG.storeKeys.riskCache);
    console.log("風險評分已快取: " + score + "% (" + source + ")");
    return { score, source };
  }

  // 1. IPQualityScore（需要 API Key）
  if (args.ipqsKey) {
    const data = await httpJSON(CONFIG.urls.ipqs(args.ipqsKey, ip));
    if (data?.success && data?.fraud_score !== undefined) {
      return saveAndReturn(data.fraud_score, "IPQS");
    }
    console.log("IPQS 回落: " + (data ? "success=" + data.success + " message=" + (data.message || "") : "請求失敗"));
  }

  // 2&3. ProxyCheck + Scamalytics 並行請求
  const [proxyData, scamHtml] = await Promise.all([
    httpJSON(CONFIG.urls.proxyCheck(ip)),
    httpRaw(CONFIG.urls.scamalytics(ip))
  ]);

  if (proxyData?.[ip]?.risk !== undefined) {
    return saveAndReturn(proxyData[ip].risk, "ProxyCheck");
  }
  console.log("ProxyCheck 失敗: " + (proxyData ? JSON.stringify(proxyData).slice(0, 100) : "請求失敗"));

  const score = parseScamalyticsScore(scamHtml);
  if (score !== null) {
    return saveAndReturn(score, "Scamalytics");
  }
  console.log("Scamalytics 失敗: " + (scamHtml ? "解析失敗" : "請求失敗"));

  return saveAndReturn(50, "Default");
}

// ==================== IP 類型偵測（二級回落） ====================
/**
 * 取得 IP 類型（住宅／機房、廣播／原生）
 * 優先順序：/v1/info JSON → /v1/card HTML 擷取
 */
async function getIPType() {
  // 1. 嘗試 /v1/info JSON 介面
  const info = await httpJSON(CONFIG.urls.ipType);
  if (info && info.isResidential !== undefined) {
    console.log("IPPure /v1/info 回傳 IP 類型資料");
    return {
      ipType: info.isResidential ? "住宅 IP" : "機房 IP",
      ipSrc: info.isBroadcast ? "廣播 IP" : "原生 IP"
    };
  }
  console.log("IPPure /v1/info 未回傳 IP 類型，回落到 /v1/card");

  // 2. 回落到 /v1/card HTML 擷取
  const html = await httpRaw(CONFIG.urls.ipTypeCard);
  if (html) {
    const ipType = /住宅|[Rr]esidential/.test(html) ? "住宅 IP" : "機房 IP";
    const ipSrc = /廣播|[Bb]roadcast|[Aa]nnounced/.test(html) ? "廣播 IP" : "原生 IP";
    console.log("IPPure /v1/card 擷取結果: " + ipType + " | " + ipSrc);
    return { ipType, ipSrc };
  }

  console.log("IPPure 所有介面均失敗");
  return { ipType: "未知", ipSrc: "未知" };
}

// ==================== IP 取得 ====================
/**
 * 取得入口／出口 IP 位址
 */
async function fetchIPs() {
  const [enter, exit, exit6] = await Promise.all([
    httpJSON(CONFIG.urls.inboundIP, "DIRECT"),
    httpJSON(CONFIG.urls.outboundIP),
    Promise.race([
      httpJSON(CONFIG.urls.outboundIPv6),
      wait(CONFIG.ipv6Timeout).then(() => null)
    ])
  ]);

  const v6ip = exit6?.ip;
  // 僅當回傳的 IP 確實為 IPv6 格式（包含 :）時才視為有效 IPv6
  // api-ipv6.ip.sb 在沒有 IPv6 連線時可能透過 IPv4 回傳相同的 IPv4 位址
  const hasIPv6 = v6ip && v6ip.includes(":");

  return {
    inIP: enter?.data?.addr || null,
    outIP: exit?.ip || null,
    outIPv6: hasIPv6 ? v6ip : null,
    inRaw: enter,
    outRaw: exit,
    v6Raw: hasIPv6 ? exit6 : null
  };
}

// ==================== 網路變更偵測 ====================
/**
 * 檢查 IP 是否發生變更（EVENT 模式）
 * @returns {boolean} true 表示有變更或非 EVENT 模式，false 表示無變更應跳過
 */
function checkIPChange(inIP, outIP, outIPv6) {
  if (!args.isEvent) return true;

  const lastEvent = $persistentStore.read(CONFIG.storeKeys.lastEvent);
  let lastData = {};
  if (lastEvent) {
    try { lastData = JSON.parse(lastEvent); } catch (e) {}
  }

  if (inIP === lastData.inIP && outIP === lastData.outIP && outIPv6 === lastData.outIP6) {
    console.log("網路資訊未變更，略過");
    return false;
  }

  console.log("網路資訊已變更");
  $persistentStore.write(JSON.stringify({ inIP, outIP, outIP6: outIPv6 }), CONFIG.storeKeys.lastEvent);
  return true;
}

// ==================== 面板內容建構 ====================
/**
 * 建構出口 IP 顯示內容
 */
function buildOutboundSection(outIP, outIPv6, outInfo, ipv6Info, isZh, isMask) {
  const lines = [];
  const ct = (info) => isZh ? info?.country_name : info?.country_code;
  const m = (ip) => isMask ? maskIP(ip) : ip;

  if (!outIPv6) {
    lines.push("出口 IP：" + m(outIP));
    lines.push("地區：" + formatGeo(outInfo?.country_code, outInfo?.city, outInfo?.region, ct(outInfo)));
    lines.push("電信商：" + (outInfo?.org || "Unknown"));
    return lines;
  }

  const sameLocation = outInfo?.country_code === ipv6Info?.country_code
    && outInfo?.org === ipv6Info?.org;

  if (sameLocation) {
    lines.push("出口 IP⁴：" + m(outIP));
    lines.push("出口 IP⁶：" + m(outIPv6));
    lines.push("地區：" + formatGeo(outInfo?.country_code, outInfo?.city, outInfo?.region, ct(outInfo)));
    lines.push("電信商：" + (outInfo?.org || "Unknown"));
  } else {
    lines.push("出口 IP⁴：" + m(outIP));
    lines.push("地區⁴：" + formatGeo(outInfo?.country_code, outInfo?.city, outInfo?.region, ct(outInfo)));
    lines.push("電信商⁴：" + (outInfo?.org || "Unknown"));
    lines.push("");
    lines.push("出口 IP⁶：" + m(outIPv6));
    lines.push("地區⁶：" + formatGeo(ipv6Info?.country_code, ipv6Info?.city, ipv6Info?.region, ct(ipv6Info)));
    lines.push("電信商⁶：" + (ipv6Info?.org || "Unknown"));
  }

  return lines;
}

/**
 * 建構完整面板內容
 */
function buildPanelContent({ isZh, isMask, riskInfo, riskResult, ipType, ipSrc, inIP, inInfo, outIP, outIPv6, outInfo, ipv6Info }) {
  const ct = (info) => isZh ? info?.country_name : info?.country_code;
  const m = (ip) => isMask ? maskIP(ip) : ip;
  const lines = [
    "IP 風控值：" + riskInfo.score + "% " + riskResult.label + " (" + riskInfo.source + ")",
    "",
    "IP 類型：" + ipType + " | " + ipSrc,
    "",
    "入口 IP：" + m(inIP),
    "地區：" + formatGeo(inInfo?.country_code, inInfo?.city, inInfo?.region, ct(inInfo)),
    "電信商：" + (inInfo?.org || "Unknown"),
    "",
    ...buildOutboundSection(outIP, outIPv6, outInfo, ipv6Info, isZh, isMask)
  ];

  return lines.join("\n");
}

// ==================== 通知內容建構 ====================
/**
 * 建構網路變更通知並送出
 */
function sendNetworkChangeNotification({ policy, inIP, outIP, inInfo, outInfo, riskInfo, riskResult, ipType, ipSrc, isMask }) {
  const m = (ip) => isMask ? maskIP(ip) : ip;
  const title = "🔄 網路已切換 | " + policy;
  const subtitle = "Ⓓ " + m(inIP) + " 🅟 " + m(outIP);
  const body = [
    "Ⓓ " + formatGeo(inInfo?.country_code, inInfo?.city, inInfo?.country_name) + " · " + (inInfo?.org || "Unknown"),
    "🅟 " + formatGeo(outInfo?.country_code, outInfo?.city, outInfo?.country_name) + " · " + (outInfo?.org || "Unknown"),
    "🅟 風控：" + riskInfo.score + "% " + riskResult.label + " | 類型：" + ipType + " · " + ipSrc
  ].join("\n");

  $notification.post(title, subtitle, body);
  console.log("=== 已送出通知 ===");
}

// ==================== 主執行函式 ====================
(async () => {
  console.log("=== IP 安全檢測開始 ===");

  // 1. EVENT 觸發時延遲等待網路穩定
  if (args.isEvent && args.eventDelay > 0) {
    console.log("等待網路穩定 " + args.eventDelay + " 秒");
    await wait(args.eventDelay * 1000);
  }

  // 2. 取得入口／出口 IP
  const { inIP, outIP, outIPv6, inRaw, outRaw, v6Raw } = await fetchIPs();

  if (!inIP || !outIP) {
    console.log("IP 取得失敗");
    return done({ title: "IP 取得失敗", content: "無法取得入口或出口 IPv4", icon: "leaf", "icon-color": "#9E9E9E" });
  }
  console.log("入口 IP: " + inIP + ", 出口 IP: " + outIP);

  // 3. EVENT 模式下檢查 IP 是否變更
  if (!checkIPChange(inIP, outIP, outIPv6)) {
    return done({});
  }

  // 4. 並行取得：代理策略、風險評分、IP 類型、地理／電信商資訊
  const isZh = args.lang === "zh";

  // 兩種模式都查 ipinfo.io（出口），zh 額外查 bilibili（中文地名）
  const queries = [
    getPolicy(),                             // 0
    getRiskScore(outIP),                     // 1
    getIPType(),                             // 2
    httpJSON(CONFIG.urls.inboundInfo(inIP)), // 3: ip.sb 入口
    httpJSON(CONFIG.urls.ipInfo(outIP))      // 4: ipinfo 出口（兩種模式都用）
  ];
  if (isZh) queries.push(httpJSON(CONFIG.urls.biliGeo(outIP)));  // 5: bilibili 出口（zh）
  const v6Idx = queries.length;
  if (outIPv6) {
    queries.push(httpJSON(CONFIG.urls.ipInfo(outIPv6)));           // v6Idx: ipinfo IPv6
    if (isZh) queries.push(httpJSON(CONFIG.urls.biliGeo(outIPv6))); // v6Idx+1: bilibili IPv6（zh）
  }

  const results = await Promise.all(queries);
  const [policy, riskInfo, ipTypeResult, inSbRaw, outIpInfoRaw] = results;

  let inInfo, outInfo, ipv6Info;
  if (isZh) {
    const outBiliRaw = results[5];
    const v6IpInfoRaw = outIPv6 ? results[v6Idx] : null;
    const v6BiliRaw = outIPv6 ? results[v6Idx + 1] : null;

    // 入口：地區用 bilibili，電信商僅中國用 bilibili，非中國用 ip.sb
    const inBili = normalizeBilibili(inRaw);
    const inSb = normalizeIpSb(inSbRaw);
    if (inBili) {
      const isChina = inBili.country_name === "中國";
      inInfo = { ...inBili, country_code: inSb?.country_code || "", org: isChina ? inBili.org : (inSb?.org || "") };
    } else {
      inInfo = inSb;
    }

    // 出口：地區用 bilibili，電信商僅中國用 bilibili，非中國用 ipinfo.io（回落 ip.sb）
    const outBili = normalizeBilibili(outBiliRaw);
    const outIpInfo = normalizeIpInfo(outIpInfoRaw);
    const outSb = normalizeIpSb(outRaw);
    if (outBili) {
      const isOutChina = outBili.country_name === "中國";
      outInfo = { ...outBili, country_code: outIpInfo?.country_code || outSb?.country_code || "", org: isOutChina ? outBili.org : (outIpInfo?.org || outSb?.org || "") };
    } else {
      outInfo = outIpInfo || outSb;
    }

    // IPv6：同上邏輯
    const v6Bili = normalizeBilibili(v6BiliRaw);
    const v6IpInfo = normalizeIpInfo(v6IpInfoRaw);
    const v6Sb = outIPv6 ? normalizeIpSb(v6Raw) : null;
    if (outIPv6) {
      if (v6Bili) {
        const isV6China = v6Bili.country_name === "中國";
        ipv6Info = { ...v6Bili, country_code: v6IpInfo?.country_code || v6Sb?.country_code || "", org: isV6China ? v6Bili.org : (v6IpInfo?.org || v6Sb?.org || "") };
      } else {
        ipv6Info = v6IpInfo || v6Sb;
      }
    } else {
      ipv6Info = null;
    }
  } else {
    // 英文模式：入口用 ip.sb，出口用 ipinfo.io（回落 ip.sb）
    const v6IpInfoRaw = outIPv6 ? results[v6Idx] : null;
    inInfo = normalizeIpSb(inSbRaw);
    outInfo = normalizeIpInfo(outIpInfoRaw) || normalizeIpSb(outRaw);
    ipv6Info = outIPv6 ? (normalizeIpInfo(v6IpInfoRaw) || normalizeIpSb(v6Raw)) : null;
  }

  const riskResult = riskText(riskInfo.score);
  const { ipType, ipSrc } = ipTypeResult;

  // 5. 依觸發類型輸出結果
  const isMask = args.maskIP;
  const context = { isZh, isMask, policy, riskInfo, riskResult, ipType, ipSrc, inIP, outIP, outIPv6, inInfo, outInfo, ipv6Info };

  if (args.isEvent) {
    sendNetworkChangeNotification(context);
    done({});
  } else {
    console.log("=== 面板顯示 ===");
    done({
      title: "代理策略：" + policy,
      content: buildPanelContent(context),
      icon: "leaf.fill",
      "icon-color": riskResult.color
    });
  }
})();
