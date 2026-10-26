// ===== Elements =====
const urlInput = document.getElementById("urlInput");
const checkBtn = document.getElementById("checkBtn");
const resultBox = document.getElementById("result");
const verdictEl = document.getElementById("verdict");
const meterFill = document.getElementById("meterFill");
const scoreText = document.getElementById("scoreText");
const reasonsList = document.getElementById("reasons");
const tipsList = document.getElementById("tipsList");

// ===== Data lists =====
const suspiciousKeywords = [
  "login", "signin", "verify", "secure", "account", "update", "bank",
  "password", "confirm", "wallet", "bonus", "lucky", "free", "gift", "reward"
];

const suspiciousTLDs = [
  "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "zip", "work", "loan", "icu"
];

const shorteners = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly"
];

// Brand ka naam host mein ho lekin asli domain na ho = impersonation
const brands = [
  { name: "paypal",    domains: ["paypal.com"] },
  { name: "google",    domains: ["google.com", "google.co.in"] },
  { name: "amazon",    domains: ["amazon.com", "amazon.in"] },
  { name: "facebook",  domains: ["facebook.com"] },
  { name: "instagram", domains: ["instagram.com"] },
  { name: "microsoft", domains: ["microsoft.com"] },
  { name: "apple",     domains: ["apple.com"] },
  { name: "netflix",   domains: ["netflix.com"] },
  { name: "paytm",     domains: ["paytm.com"] },
  { name: "sbi",       domains: ["sbi.co.in", "onlinesbi.sbi"] },
  { name: "hdfc",      domains: ["hdfcbank.com"] },
  { name: "icici",     domains: ["icicibank.com"] }
];

const tips = [
  "Link par click karne se pehle URL ko dhyan se padho, spelling ki galtiyan dekho (paypa1.com, amaz0n.in).",
  "Bank ya government kabhi SMS/email se password, OTP ya PIN nahi maangte.",
  "Address bar mein HTTPS aur lock icon dekho, lekin sirf wahi safe hone ki guarantee nahi hai.",
  "Urgent messages (\"account block ho jayega\") se ghabrao mat, ye social engineering ka tareeka hai.",
  "Shortened links (bit.ly etc.) kholne se pehle preview karo ya expand karke check karo.",
  "Unknown attachments ya apps download mat karo, aur software ko hamesha update rakho.",
  "Jahan possible ho, Multi-Factor Authentication (MFA) on rakho."
];

// ===== Main analysis function =====
function analyzeURL(raw) {
  let input = raw.trim();
  if (!input) return { error: "Pehle koi URL daalo." };

  // Agar scheme nahi hai to https laga do (aur HTTPS check skip karenge)
  let hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(input);
  if (!hasScheme) input = "https://" + input;

  let url;
  try {
    url = new URL(input);
  } catch (e) {
    return { error: "Ye valid URL nahi lag raha. Dobara check karo." };
  }

  const host = url.hostname.toLowerCase();
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);

  if (!isIP && !host.includes(".")) {
    return { error: "Ye valid URL nahi lag raha. Dobara check karo." };
  }

  let score = 0;
  const reasons = [];

  // 1. HTTPS check
  if (hasScheme && url.protocol !== "https:") {
    score += 15;
    reasons.push("HTTPS nahi hai, connection encrypted nahi hai (+15)");
  }

  // 2. IP address as host
  if (isIP) {
    score += 25;
    reasons.push("Domain ki jagah IP address use hua hai (+25)");
  }

  // 3. '@' symbol
  if (input.includes("@")) {
    score += 20;
    reasons.push("URL mein '@' hai, asli destination chhupane ke liye use hota hai (+20)");
  }

  // 4. URL length
  if (input.length > 75) {
    score += 10;
    reasons.push("URL bahut lamba hai (" + input.length + " characters) (+10)");
  }

  // 5. Too many subdomains
  if (!isIP && host.split(".").length > 4) {
    score += 10;
    reasons.push("Bahut zyada subdomains hain (+10)");
  }

  // 6. Hyphens in domain
  const hyphens = (host.match(/-/g) || []).length;
  if (hyphens >= 2) {
    score += 10;
    reasons.push("Domain mein " + hyphens + " hyphens (-) hain (+10)");
  }

  // 7. Suspicious keywords (host + path)
  const target = (host + url.pathname).toLowerCase();
  const found = suspiciousKeywords.filter(k => target.includes(k));
  if (found.length > 0) {
    const pts = Math.min(found.length * 5, 20);
    score += pts;
    reasons.push("Suspicious words mile: " + found.join(", ") + " (+" + pts + ")");
  }

  // 8. Suspicious TLD
  const tld = host.split(".").pop();
  if (!isIP && suspiciousTLDs.includes(tld)) {
    score += 15;
    reasons.push("Domain ka ending ." + tld + " aksar spam/phishing mein use hota hai (+15)");
  }

  // 9. URL shortener
  if (shorteners.includes(host)) {
    score += 15;
    reasons.push("URL shortener use hua hai, asli link chhupa hua hai (+15)");
  }

  // 10. Punycode (lookalike characters)
  if (host.includes("xn--")) {
    score += 15;
    reasons.push("Punycode domain hai, lookalike characters ho sakte hain (+15)");
  }

  // 11. Non-standard port
  if (url.port !== "") {
    score += 10;
    reasons.push("Unusual port (" + url.port + ") use hua hai (+10)");
  }

  // 12. Brand impersonation
  for (const b of brands) {
    const isReal = b.domains.some(d => host === d || host.endsWith("." + d));
    if (host.includes(b.name) && !isReal) {
      score += 25;
      reasons.push("'" + b.name + "' ka naam hai, par asli " + b.name + " domain nahi hai (+25)");
      break;
    }
  }

  if (score > 100) score = 100;
  if (reasons.length === 0) reasons.push("Koi red flag nahi mila.");

  return { score, reasons };
}

// ===== Show result on page =====
function showResult(data) {
  resultBox.classList.remove("hidden");
  reasonsList.innerHTML = "";

  // Error case
  if (data.error) {
    resultBox.className = "result";
    verdictEl.textContent = data.error;
    meterFill.style.width = "0%";
    scoreText.textContent = "";
    return;
  }

  let cls, text;
  if (data.score >= 60) {
    cls = "danger";
    text = "🚨 Dangerous: phishing hone ke chances zyada hain";
  } else if (data.score >= 30) {
    cls = "suspicious";
    text = "⚠️ Suspicious: sambhal ke, click mat karo";
  } else {
    cls = "safe";
    text = "✅ Looks Safe (par 100% guarantee nahi)";
  }

  resultBox.className = "result " + cls;
  verdictEl.textContent = text;
  meterFill.style.width = data.score + "%";
  scoreText.textContent = "Risk score: " + data.score + " / 100";

  data.reasons.forEach(r => {
    const li = document.createElement("li");
    li.textContent = r;
    reasonsList.appendChild(li);
  });
}

// ===== Tips =====
tips.forEach(t => {
  const li = document.createElement("li");
  li.textContent = t;
  tipsList.appendChild(li);
});

// ===== Events =====
checkBtn.addEventListener("click", () => {
  showResult(analyzeURL(urlInput.value));
});

urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    showResult(analyzeURL(urlInput.value));
  }
});