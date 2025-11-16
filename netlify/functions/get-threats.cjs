// netlify/functions/get-threats.cjs
const axios = require('axios');
const Parser = require('rss-parser');
const parser = new Parser();

const OTX_KEY = process.env.OTX_API_KEY;
const VT_KEY = process.env.VT_API_KEY;
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_API_KEY;

if (!OTX_KEY || !VT_KEY || !ABUSEIPDB_KEY) {
  console.error('Missing API keys');
  exports.handler = async () => ({
    statusCode: 500,
    body: JSON.stringify({ error: 'Missing API keys' })
  });
  return;
}

const RSS_FEEDS = [
  'https://www.wired.com/feed/category/security/latest/rss',
  'https://www.thehackernews.com/feeds/posts/default',
  'https://www.zdnet.com/topic/security/rss.xml',
  'https://feeds.arstechnica.com/arstechnica/index/',
  'https://threatpost.com/feed/',
  'https://krebsonsecurity.com/feed/atom/',
  'https://www.bleepingcomputer.com/feed/',
  'https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v'
];

let cache = { threats: [], zeroDays: [], lastUpdate: 0 };
const CACHE_TTL = 15 * 60 * 1000;

async function fetchData() {
  const now = Date.now();
  if (cache.lastUpdate > now - CACHE_TTL) return cache;

  const zeroDays = [];
  const threats = [];

  // RSS + CISA KEV
  for (const url of RSS_FEEDS) {
    try {
      const feed = await parser.parseURL(url);
      feed.items.slice(0, 3).forEach(item => {
        const match = item.title.match(/CVE[-–]?(\d{4}-\d{4,7})/i);
        if (match) {
          zeroDays.push({
            cve: `CVE-${match[1]}`,
            product: item.title.includes('Microsoft') ? 'Microsoft' : 'Unknown',
            dateAdded: new Date(item.pubDate).toISOString().split('T')[0],
            source: feed.title.split(' - ')[0],
            link: item.link
          });
        }
      });
    } catch (e) {}
  }

  try {
    const kev = await axios.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    kev.data.vulnerabilities.slice(0, 15).forEach(v => {
      zeroDays.push({
        cve: v.cveID,
        product: v.vendorProject,
        dateAdded: v.dateAdded,
        source: 'CISA KEV',
        link: `https://nvd.nist.gov/vuln/detail/${v.cveID}`
      });
    });
  } catch (e) {}

  const uniqueZeroDays = [...new Map(zeroDays.map(z => [z.cve, z])).values()]
    .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded))
    .slice(0, 25);

  // Threats
  try {
    const otx = await axios.get('https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10', {
      headers: { 'X-OTX-API-KEY': OTX_KEY }
    });

    for (const p of otx.data.results) {
      const ip = '198.51.100.1';
      const [vt, abuse] = await Promise.all([
        axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, { headers: { 'x-apikey': VT_KEY } }).catch(() => ({ data: { data: { attributes: { last_analysis_stats: { malicious: 0 } } } } })),
        axios.get(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=7`, { headers: { Key: ABUSEIPDB_KEY } }).catch(() => ({ data: { data: { abuseConfidenceScore: 0 } } }))
      ]);

      const score = abuse.data.data.abuseConfidenceScore;
      threats.push({
        id: p.id,
        type: p.tags[0] || 'malware',
        severity: score > 70 ? 'Critical' : score > 40 ? 'High' : 'Medium',
        summary: p.name,
        lastSeen: p.modified,
        sourceUrl: `https://otx.alienvault.com/pulse/${p.id}`,
        source: 'OTX'
      });
    }
  } catch (e) {
    threats.push({
      id: 'mock',
      type: 'ransomware',
      severity: 'Critical',
      summary: 'Simulated LockBit (fallback)',
      lastSeen: new Date().toISOString(),
      sourceUrl: '#',
      source: 'Mock'
    });
  }

  cache = { threats: threats.slice(0, 25), zeroDays: uniqueZeroDays, lastUpdate: now };
  return cache;
}

exports.handler = async () => {
  try {
    const data = await fetchData();
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Server error' }) };
  }
};