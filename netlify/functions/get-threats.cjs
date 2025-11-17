// netlify/functions/get-threats.cjs
const axios = require('axios');
const Parser = require('rss-parser');
const parser = new Parser({
  customFields: { item: ['contentSnippet', 'content:encoded'] }
});

const OTX_KEY = process.env.OTX_API_KEY;
const VT_KEY = process.env.VT_API_KEY;
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_API_KEY;

// Validate keys
if (!OTX_KEY || !VT_KEY || !ABUSEIPDB_KEY) {
  console.error('[INIT] Missing API keys');
  exports.handler = async () => ({ statusCode: 500, body: JSON.stringify({ error: 'Missing keys' }) });
  return;
}

// Decode HTML
function decodeHtmlEntities(text) {
  if (!text) return '';
  const entities = { '&quot;': '"', '&amp;': '&', '&lt;': '<', '&gt;': '>', '&apos;': "'", '&#8217;': "'", '&#8220;': '"', '&#10;': ' ' };
  return text.replace(/&#?[xX]?[0-9a-fA-F]+;/g, m => entities[m.toLowerCase()] || m).replace(/\s+/g, ' ').trim();
}

const RSS_FEEDS = [
  'https://www.wired.com/feed/category/security/latest/rss',
  'https://www.thehackernews.com/feeds/posts/default',
  'https://feeds.arstechnica.com/arstechnica/index/',
  'https://threatpost.com/feed/',
  'https://krebsonsecurity.com/feed/atom/',
  'https://www.bleepingcomputer.com/feed/',
  'https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v',
  'https://www.cisa.gov/cybersecurity-advisories/all.xml',
  'https://isc.sans.edu/rssfeed.xml',
  'https://www.darkreading.com/rss.xml'
];

const MISP_FEEDS = [
  { url: 'http://reputation.alienvault.com/reputation.data', name: 'DShield Top Attackers', type: 'txt' },
  { url: 'https://www.spamhaus.org/drop/drop.txt', name: 'Spamhaus DROP', type: 'txt' },
  { url: 'https://threatfox.abuse.ch/export/csv/recent/', name: 'ThreatFox Recent', type: 'csv' }
];

let cache = { threats: [], zeroDays: [], lastUpdate: 0, ipEnrichmentCache: {} };
const CACHE_TTL = 15 * 60 * 1000;
const VT_RATE_LIMIT_DELAY = 15000;
let lastVTCall = 0;

async function getVTData(ip) {
  if (cache.ipEnrichmentCache[ip]?.vt !== undefined) return cache.ipEnrichmentCache[ip].vt;
  const now = Date.now();
  if (now - lastVTCall < VT_RATE_LIMIT_DELAY) await new Promise(r => setTimeout(r, VT_RATE_LIMIT_DELAY - (now - lastVTCall)));
  try {
    lastVTCall = Date.now();
    const res = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, { headers: { 'x-apikey': VT_KEY }, timeout: 5000 });
    const malicious = res.data?.data?.attributes?.last_analysis_stats?.malicious || 0;
    if (!cache.ipEnrichmentCache[ip]) cache.ipEnrichmentCache[ip] = {};
    cache.ipEnrichmentCache[ip].vt = malicious;
    return malicious;
  } catch { return 0; }
}

async function getAbuseIPDBData(ip) {
  if (cache.ipEnrichmentCache[ip]?.abuse !== undefined) return cache.ipEnrichmentCache[ip].abuse;
  try {
    const res = await axios.get('https://api.abuseipdb.com/api/v2/check', { params: { ipAddress: ip, maxAgeInDays: 90 }, headers: { Key: ABUSEIPDB_KEY }, timeout: 5000 });
    const score = res.data?.data?.abuseConfidenceScore || 0;
    if (!cache.ipEnrichmentCache[ip]) cache.ipEnrichmentCache[ip] = {};
    cache.ipEnrichmentCache[ip].abuse = score;
    return score;
  } catch { return 0; }
}

function classifyThreat(item) {
  const text = `${item.title} ${item.contentSnippet || ''}`.toLowerCase();
  const critical = ['zero-day', 'actively exploited', 'ransomware attack', 'nation-state'];
  const high = ['rce', 'privilege escalation', 'sql injection', 'exploit in the wild'];
  if (critical.some(k => text.includes(k))) return 'Critical';
  if (high.some(k => text.includes(k))) return 'High';
  if (text.match(/cve[-–]?\d{4}[-–]?\d{4,7}/i)) return 'Medium';
  return 'Low';
}

function determineThreatType(item) {
  const text = `${item.title} ${item.contentSnippet || ''}`.toLowerCase();
  if (text.includes('ransomware')) return 'ransomware';
  if (text.includes('phishing')) return 'phishing';
  if (text.includes('malware')) return 'malware';
  if (text.includes('vulnerability') || text.includes('cve')) return 'vulnerability';
  return 'threat-intel';
}

function extractFirstIP(indicators) {
  if (!indicators || !Array.isArray(indicators)) return null;
  const ipTypes = ['IPv4', 'IPV4', 'ip', 'IP', 'ip-dst', 'ip-src'];
  const ipInd = indicators.find(i => i.type && ipTypes.some(t => i.type.toLowerCase() === t.toLowerCase()));
  if (ipInd && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ipInd.indicator)) return ipInd.indicator;
  const match = indicators.find(i => i.indicator && i.indicator.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/));
  return match ? match.indicator.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/)[1] : null;
}

function parseTxtFeed(data) {
  return data.split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'))
    .map(l => l.split(/\s+/)[0].split('#')[0])
    .filter(i => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(i) || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(i))
    .slice(0, 3);
}

function parseCsvFeed(data) {
  return data.split('\n').slice(1)
    .map(l => l.split(',')[0].replace(/"/g, '').trim())
    .filter(i => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(i) || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(i) || /^[a-f0-9]{32,64}$/i.test(i))
    .slice(0, 3);
}

async function fetchData() {
  const now = Date.now();
  if (cache.lastUpdate > now - CACHE_TTL) return cache;

  const zeroDays = [];
  const threats = [];
  const seenIOCs = new Set();

  // === PARALLEL RSS ===
  const rssPromises = RSS_FEEDS.map(async (url) => {
    try {
      const feed = await parser.parseURL(url);
      const source = feed.title?.split(' - ')[0] || url.split('/')[2];
      return feed.items.slice(0, 10).map(item => {
        const date = new Date(item.pubDate || item.isoDate);
        if (date < new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)) return null;
        const title = item.title || '';
        const cveMatch = title.match(/CVE[-–]?(\d{4}-\d{4,7})/i);
        if (cveMatch) {
          zeroDays.push({
            cve: `CVE-${cveMatch[1]}`,
            product: title.includes('Microsoft') ? 'Microsoft' : title.includes('Google') ? 'Google' : title.includes('Apple') ? 'Apple' : 'Unknown',
            dateAdded: date.toISOString().split('T')[0],
            source,
            link: item.link
          });
        }
        return {
          id: `rss-${Buffer.from(item.link).toString('base64').slice(0, 10)}`,
          type: determineThreatType(item),
          severity: classifyThreat(item),
          summary: decodeHtmlEntities(title.slice(0, 150)),
          lastSeen: date.toISOString(),
          sourceUrl: item.link,
          source
        };
      }).filter(Boolean);
    } catch { return []; }
  });
  const rssThreats = (await Promise.all(rssPromises)).flat();

  // === CISA KEV ===
  try {
    const kev = await axios.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { timeout: 5000 });
    kev.data.vulnerabilities.slice(0, 15).forEach(v => {
      zeroDays.push({ cve: v.cveID, product: v.vendorProject, dateAdded: v.dateAdded, source: 'CISA KEV', link: `https://nvd.nist.gov/vuln/detail/${v.cveID}` });
    });
  } catch {}

  const uniqueZeroDays = [...new Map(zeroDays.map(z => [z.cve, z])).values()]
    .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded))
    .slice(0, 25);

  // === OTX (LIMIT ENRICHMENT) ===
  try {
    const otx = await axios.get('https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10', { headers: { 'X-OTX-API-KEY': OTX_KEY }, timeout: 8000 });
    for (const p of otx.data.results) {
      const ip = extractFirstIP(p.indicators || []);
      let enrichment = '';
      let severity = 'Medium';

      if (ip && !seenIOCs.has(ip) && Object.keys(cache.ipEnrichmentCache).length < 8) {
        seenIOCs.add(ip);
        const [vt, abuse] = await Promise.all([getVTData(ip), getAbuseIPDBData(ip)]);
        enrichment = ` | ${ip} | VT: ${vt} malicious | Abuse: ${abuse}%`;
        severity = abuse > 80 || vt > 10 ? 'Critical' : abuse > 50 || vt > 3 ? 'High' : 'Medium';
      }

      const tags = (p.tags || []).join(' ').toLowerCase();
      const desc = (p.description || '').toLowerCase();
      const combined = `${tags} ${desc} ${p.name}`.toLowerCase();
      if (combined.includes('zero-day') || combined.includes('ransomware attack')) severity = 'Critical';

      threats.push({
        id: p.id,
        type: p.tags[0] || 'malware',
        severity,
        summary: decodeHtmlEntities(p.name) + enrichment,
        lastSeen: p.modified,
        sourceUrl: `https://otx.alienvault.com/pulse/${p.id}`,
        source: 'OTX'
      });
    }
  } catch {}

  // === PARALLEL MISP ===
  const mispPromises = MISP_FEEDS.map(async (feed) => {
    try {
      const res = await axios.get(feed.url, { timeout: 5000 });
      const iocs = feed.type === 'csv' ? parseCsvFeed(res.data) : parseTxtFeed(res.data);
      return iocs.map(ioc => {
        if (seenIOCs.has(ioc)) return null;
        seenIOCs.add(ioc);
        return {
          id: `misp-${Buffer.from(ioc).toString('base64').slice(0, 10)}`,
          type: 'threat-intel',
          severity: 'High',
          summary: `IOC: ${ioc} from ${feed.name}`,
          lastSeen: new Date().toISOString(),
          sourceUrl: feed.url,
          source: 'MISP Feed'
        };
      }).filter(Boolean);
    } catch { return []; }
  });
  const mispThreats = (await Promise.all(mispPromises)).flat();

  // === FINAL ===
  const allThreats = [...threats, ...rssThreats, ...mispThreats]
    .sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime())
    .slice(0, 25);

  cache = { threats: allThreats, zeroDays: uniqueZeroDays, lastUpdate: now, ipEnrichmentCache: cache.ipEnrichmentCache };
  return cache;
}

exports.handler = async () => {
  try {
    const data = await fetchData();
    return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) };
  } catch (e) {
    console.error('Handler error:', e);
    return { statusCode: 500, body: JSON.stringify({ error: 'Server error' }) };
  }
};