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
  'https://feeds.arstechnica.com/arstechnica/index/',
  'https://threatpost.com/feed/',
  'https://krebsonsecurity.com/feed/atom/',
  'https://www.bleepingcomputer.com/feed/',
  'https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v'
];

let cache = { threats: [], zeroDays: [], lastUpdate: 0 };
const CACHE_TTL = 15 * 60 * 1000;

// Classify severity based on threat indicators in content
function classifyThreat(item) {
  const text = `${item.title} ${item.contentSnippet || ''}`.toLowerCase();
  
  // Critical indicators - immediate, severe, widespread threats
  const critical = [
    'zero-day', 'zero day', 'actively exploited', 'active exploitation',
    'ransomware', 'critical vulnerability', 'supply chain attack',
    'apt', 'advanced persistent', 'nation-state', 'state-sponsored',
    'wormable', 'mass exploitation'
  ];
  
  // High severity indicators - serious threats requiring prompt action
  const high = [
    'remote code execution', 'rce', 'privilege escalation',
    'authentication bypass', 'sql injection', 'data breach',
    'malware campaign', 'phishing campaign', 'botnet',
    'credential theft', 'lateral movement', 'backdoor'
  ];
  
  // Medium severity indicators - notable but contained threats
  const medium = [
    'vulnerability', 'exploit', 'malware', 'trojan',
    'security flaw', 'unauthorized access', 'exposed database',
    'misconfiguration', 'ddos', 'brute force', 'information disclosure'
  ];
  
  // Low severity indicators - awareness, patches, minor issues
  const low = [
    'patch', 'update available', 'advisory', 'disclosure',
    'security tip', 'recommendation', 'best practice',
    'awareness', 'warning', 'announcement', 'guidance',
    'tutorial', 'how to protect', 'prevention'
  ];
  
  // Check for critical
  if (critical.some(keyword => text.includes(keyword))) {
    return 'Critical';
  }
  
  // Check for high
  if (high.some(keyword => text.includes(keyword))) {
    return 'High';
  }
  
  // Check for CVE mentions (usually high severity)
  if (text.match(/cve[-–]?\d{4}[-–]?\d{4,7}/i)) {
    return 'High';
  }
  
  // Check for medium
  if (medium.some(keyword => text.includes(keyword))) {
    return 'Medium';
  }
  
  // Check for low
  if (low.some(keyword => text.includes(keyword))) {
    return 'Low';
  }
  
  // If no indicators found, default to Low (likely informational)
  return 'Low';
}

// Determine threat type from content
function determineThreatType(item) {
  const text = `${item.title} ${item.contentSnippet || ''}`.toLowerCase();
  
  if (text.includes('ransomware')) return 'ransomware';
  if (text.includes('phishing')) return 'phishing';
  if (text.includes('malware') || text.includes('trojan')) return 'malware';
  if (text.includes('ddos') || text.includes('botnet')) return 'ddos';
  if (text.includes('vulnerability') || text.includes('cve')) return 'vulnerability';
  if (text.includes('breach') || text.includes('leak')) return 'data-breach';
  if (text.includes('apt') || text.includes('state-sponsored')) return 'apt';
  
  return 'threat-intel';
}

async function fetchData() {
  const now = Date.now();
  if (cache.lastUpdate > now - CACHE_TTL) return cache;

  const zeroDays = [];
  const threats = [];

  // Parse RSS feeds for both threats AND zero-days
  for (const url of RSS_FEEDS) {
    try {
      const feed = await parser.parseURL(url);
      const sourceName = feed.title?.split(' - ')[0] || url.split('/')[2];
      
      feed.items.slice(0, 5).forEach(item => {
        // Check for CVE (for zero-days)
        const cveMatch = item.title.match(/CVE[-–]?(\d{4}-\d{4,7})/i);
        if (cveMatch) {
          zeroDays.push({
            cve: `CVE-${cveMatch[1]}`,
            product: item.title.includes('Microsoft') ? 'Microsoft' : 
                     item.title.includes('Google') ? 'Google' :
                     item.title.includes('Apple') ? 'Apple' : 'Unknown',
            dateAdded: new Date(item.pubDate || item.isoDate).toISOString().split('T')[0],
            source: sourceName,
            link: item.link
          });
        }
        
        // Add as threat (from RSS feeds)
        threats.push({
          id: `rss-${Buffer.from(item.link).toString('base64').slice(0, 10)}`,
          type: determineThreatType(item),
          severity: classifyThreat(item),
          summary: item.title.slice(0, 150),
          lastSeen: new Date(item.pubDate || item.isoDate).toISOString(),
          sourceUrl: item.link,
          source: sourceName
        });
      });
    } catch (e) {
      console.error(`Error parsing ${url}:`, e.message);
    }
  }

  // Add CISA KEV
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
  } catch (e) {
    console.error('Error fetching CISA KEV:', e.message);
  }

  const uniqueZeroDays = [...new Map(zeroDays.map(z => [z.cve, z])).values()]
    .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded))
    .slice(0, 25);

  // Fetch OTX threats with real severity classification
  try {
    const otx = await axios.get('https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10', {
      headers: { 'X-OTX-API-KEY': OTX_KEY }
    });

    for (const p of otx.data.results) {
      // Use actual indicators from the pulse
      const indicators = p.indicators || [];
      const hasIPs = indicators.some(i => i.type === 'IPv4' || i.type === 'IPv6');
      
      // Classify based on tags and content
      let severity = 'Low';
      const tags = (p.tags || []).join(' ').toLowerCase();
      const description = (p.description || '').toLowerCase();
      const combined = `${tags} ${description} ${p.name}`.toLowerCase();
      
      if (combined.includes('critical') || combined.includes('ransomware') || 
          combined.includes('zero-day') || combined.includes('apt')) {
        severity = 'Critical';
      } else if (combined.includes('high') || combined.includes('exploit') || 
                 combined.includes('malware') || hasIPs) {
        severity = 'High';
      } else if (combined.includes('vulnerability') || combined.includes('threat') ||
                 combined.includes('attack') || combined.includes('campaign')) {
        severity = 'Medium';
      }
      // Otherwise stays 'Low' for general advisories

      threats.push({
        id: p.id,
        type: p.tags[0] || 'malware',
        severity: severity,
        summary: p.name,
        lastSeen: p.modified,
        sourceUrl: `https://otx.alienvault.com/pulse/${p.id}`,
        source: 'OTX'
      });
    }
  } catch (e) {
    console.error('Error fetching OTX:', e.message);
    // Add fallback mock data
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

  // Sort threats by severity (Critical > High > Medium > Low) and date
  const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3 };
  const sortedThreats = threats
    .sort((a, b) => {
      const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (severityDiff !== 0) return severityDiff;
      return new Date(b.lastSeen) - new Date(a.lastSeen);
    })
    .slice(0, 25);

  cache = { threats: sortedThreats, zeroDays: uniqueZeroDays, lastUpdate: now };
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
    console.error('Handler error:', e);
    return { statusCode: 500, body: JSON.stringify({ error: 'Server error' }) };
  }
};