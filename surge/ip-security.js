/**
 * Surge IP Security Check Script
 *
 * 功能概述：
 * - 檢測並顯示入口/出口 IP 資訊
 * - 評估 IP 風險等級和類型
 * - 顯示地理位置和電信業者資訊
 * - 支援網路變化自動檢測和通知
 *
 * 數據來源：
 * ① 入口 IP: bilibili API (DIRECT)
 * ② 出口 IP: ip.sb API (IPv4/IPv6)
 * ③ 代理策略: Surge /v1/requests/recent
 * ④ 風險評分: IPQualityScore (主，需 API) → ProxyCheck (備) → Scamalytics (兜底)
 * ⑤ IP 類型: IPPure API
 * ⑥ 地理/電信業者: lang=en → ipinfo.io + ip.sb | lang=zh → bilibili (中文, ip.sb 兜底)
 *
 * 參數說明：
 * - TYPE: 設為 EVENT 表示網路變化觸發（自動判斷，無需手動設置）
 * - ipqs_key: IPQualityScore API Key (可選)
 * - lang: 地理資訊語言，en(預設)=英文(ipinfo.io)，zh=中文(bilibili)
 * - event_delay: 網路變化後延遲檢測（秒），預設 2 秒
 *
 * 配置示例：
 * [Panel]
 * ip-security-panel = script-name=ip-security-panel,update-interval=600
 *
 * [Script]
 * # 手動觸發（面板）
 * ip-security-panel = type=generic,timeout=10,script-path=ip-security.js,argument=ipqs_key=YOUR_API_KEY
 *
 * # 網路變化自動觸發
 * ip-security-event = type=event,event-name=network-changed,timeout=10,script-path=ip-security.js,argument=TYPE=EVENT&ipqs_key=YOUR_API_KEY&event_delay=2
 *
 * @author HotKids&Claude
 * @version 4.0.0
 * @date 2026-02-09
 */

// ==================== 全局配置 ====================
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
    eventDelay: parseFloat(arg.event_delay) || 2
  };
}

const args = parseArguments();
console.log("觸發類型: " + (args.isEvent ? "EVENT" : "MANUAL") + ", 語言: " + args.lang);

// ==================== 全局狀態控制 ====================
let finished = false;

function done(o) {
  if (finished) return;
  finished = true;
  $done(o);
}

setTimeout(() => {
  done({ title: "檢測超時", content: "API 請求超時", icon: "leaf", "icon-color": "#9E9E9E" });
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

// ==================== 數據處理工具 ====================
/**
 * 將國家代碼轉換為國旗 emoji
 */
function flag(cc) {
  if (!cc || cc.length !== 2) return "";
  if (cc.toUpperCase() === "TW") cc = "TW"; // 保持台灣國旗
  const b = 0x1f1e6;
  return String.fromCodePoint(b + cc.charCodeAt(0) - 65, b + cc.charCodeAt(1) - 65);
}

/**
 * 根據風險分數返回對應的描述和顏色
 */
function riskText(score) {
  const level = CONFIG.riskLevels.find(l => score <= l.max) || CONFIG.riskLevels.at(-1);
  return { label: level.label, color: level.color };
}

/**
 * 格式化地理位置文本：🇺🇸 + 自定義部分
 */
function formatGeo(countryCode, ...parts) {
  return flag(countryCode) + " " + parts.filter(Boolean).join(", ");
}

/**
 * 將 ip.sb 返回欄位歸一化為內部格式
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
 * 將 ipinfo.io 返回欄位歸一化為內部格式
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
 * 將 bilibili zone API 返回欄位歸一化為內部格式（繁體化）
 */
function normalizeBilibili(data) {
  const d = data?.data;
  if (!d || !d.country) return null;
  let isp = d.isp || "";
  if (/^(移動|聯通|電信|廣電)$/.test(isp)) isp = "中國" + isp;
  return {
    country_code: null,
    country_name: d.country.replace("中国", "中國"),
    city: d.city || d.province,
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

// ==================== 代理策略獲取 ====================
/**
 * 從 Surge 最近請求中查找匹配的代理策略
 */
async function findPolicyInRecent(pattern, limit) {
  const res = await surgeAPI("GET", "/v1/requests/recent");
  const hit = res?.requests?.slice(0, limit).find(i => pattern.test(i.URL));
  return hit?.policyName || null;
}

/**
 * 獲取實際使用的代理策略（帶重試和回退）
 */
async function getPolicy() {
  let policy = await findPolicyInRecent(/(api(-ipv4)?\.ip\.sb|ipinfo\.io)/i, 10);
  if (policy) {
    console.log("找到代理策略: " + policy);
    $persistentStore.write(policy, CONFIG.storeKeys.lastPolicy);
    return policy;
  }

  console.log("未找到策略記錄，等待後重試");
  await wait(CONFIG.policyRetryDelay);

  policy = await findPolicyInRecent(/(api(-ipv4)?\.ip\.sb|ipinfo\.io)/i, 5);
  if (policy) {
    console.log("重試後找到策略: " + policy);
    $persistentStore.write(policy, CONFIG.storeKeys.lastPolicy);
    return policy;
  }

  const lastPolicy = $persistentStore.read(CONFIG.storeKeys.lastPolicy);
  if (lastPolicy) {
    console.log("使用上次保存的策略: " + lastPolicy);
    return lastPolicy;
  }

  console.log("無法找到任何策略資訊");
  return "Unknown";
}

// ==================== 風險評分獲取（三級回退） ====================
async function getRiskScore(ip) {
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

  if (args.ipqsKey) {
    const data = await httpJSON(CONFIG.urls.ipqs(args.ipqsKey, ip));
    if (data?.success && data?.fraud_score !== undefined) {
      return saveAndReturn(data.fraud_score, "IPQS");
    }
    console.log("IPQS 回退: " + (data ? "success=" + data.success + " message=" + (data.message || "") : "請求失敗"));
  }

  const [proxyData, scamHtml] = await Promise.all([
    httpJSON(CONFIG.urls.proxyCheck(ip)),
    httpRaw(CONFIG.urls.scamalytics(ip))
  ]);

  if (proxyData?.[ip]?.risk !== undefined) {
    return saveAndReturn(proxyData[ip].risk, "ProxyCheck");
  }
  console.log("ProxyCheck 失敗");

  const score = parseScamalyticsScore(scamHtml);
  if (score !== null) {
    return saveAndReturn(score, "Scamalytics");
  }

  return saveAndReturn(50, "Default");
}

// ==================== IP 類型檢測 ====================
async function getIPType() {
  const info = await httpJSON(CONFIG.urls.ipType);
  if (info && info.isResidential !== undefined) {
    console.log("IPPure /v1/info 返回 IP 類型數據");
    return {
      ipType: info.isResidential ? "住宅 IP" : "機房 (DC) IP",
      ipSrc: info.isBroadcast ? "廣播 IP" : "原生 IP"
    };
  }

  const html = await httpRaw(CONFIG.urls.ipTypeCard);
  if (html) {
    const ipType = /住宅|[Rr]esidential/.test(html) ? "住宅 IP" : "機房 (DC) IP";
    const ipSrc = /廣播|[Bb]roadcast|[Aa]nnounced/.test(html) ? "廣播 IP" : "原生 IP";
    return { ipType, ipSrc };
  }

  return { ipType: "未知", ipSrc: "未知" };
}

// ==================== IP 獲取 ====================
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

// ==================== 網路變化檢測 ====================
function checkIPChange(inIP, outIP, outIPv6) {
  if (!args.isEvent) return true;

  const lastEvent = $persistentStore.read(CONFIG.storeKeys.lastEvent);
  let lastData = {};
  if (lastEvent) {
    try { lastData = JSON.parse(lastEvent); } catch (e) {}
  }

  if (inIP === lastData.inIP && outIP === lastData.outIP && outIPv6 === lastData.outIP6) {
    console.log("網路資訊未變化，跳過");
    return false;
  }

  console.log("網路資訊已變化");
  $persistentStore.write(JSON.stringify({ inIP, outIP, outIP6: outIPv6 }), CONFIG.storeKeys.lastEvent);
  return true;
}

// ==================== 面板內容構建 ====================
function buildOutboundSection(outIP, outIPv6, outInfo, ipv6Info, isZh) {
  const lines = [];
  const ct = (info) => isZh ? info?.country_name : info?.country_code;

  if (!outIPv6) {
    lines.push("出口 IP：" + outIP);
    lines.push("地區：" + formatGeo(outInfo?.country_code, outInfo?.city, outInfo?.region, ct(outInfo)));
    lines.push("電信業者：" + (outInfo?.org || "Unknown"));
    return lines;
  }

  const sameLocation = outInfo?.country_code === ipv6Info?.country_code
    && outInfo?.org === ipv6Info?.org;

  if (sameLocation) {
    lines.push("出口 IP⁴：" + outIP);
    lines.push("出口 IP⁶：" + outIPv6);
    lines.push("地區：" + formatGeo(outInfo?.country_code, outInfo?.city, outInfo?.region, ct(outInfo)));
    lines.push("電信業者：" + (outInfo?.org || "Unknown"));
  } else {
    lines.push("出口 IP⁴：" + outIP);
    lines.push("地區⁴：" + formatGeo(outInfo?.country_code, outInfo?.city, outInfo?.region, ct(outInfo)));
    lines.push("電信業者⁴：" + (outInfo?.org || "Unknown"));
    lines.push("");
    lines.push("出口 IP⁶：" + outIPv6);
    lines.push("地區⁶：" + formatGeo(ipv6Info?.country_code, ipv6Info?.city, ipv6Info?.region, ct(ipv6Info)));
    lines.push("電信業者⁶：" + (ipv6Info?.org || "Unknown"));
  }

  return lines;
}

function buildPanelContent({ isZh, riskInfo, riskResult, ipType, ipSrc, inIP, inInfo, outIP, outIPv6, outInfo, ipv6Info }) {
  const ct = (info) => isZh ? info?.country_name : info?.country_code;
  const lines = [
    "IP 風控值：" + riskInfo.score + "% " + riskResult.label + " (" + riskInfo.source + ")",
    "",
    "IP 類型：" + ipType + " | " + ipSrc,
    "",
    "入口 IP：" + inIP,
    "地區：" + formatGeo(inInfo?.country_code, inInfo?.city, inInfo?.region, ct(inInfo)),
    "電信業者：" + (inInfo?.org || "Unknown"),
    "",
    ...buildOutboundSection(outIP, outIPv6, outInfo, ipv6Info, isZh)
  ];

  return lines.join("\n");
}

// ==================== 通知內容構建 ====================
function sendNetworkChangeNotification({ policy, inIP, outIP, inInfo, outInfo, riskInfo, riskResult, ipType, ipSrc }) {
  const title = "🔄
