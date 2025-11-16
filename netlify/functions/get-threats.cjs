// netlify/functions/get-threats.cjs
const axios = require('axios');
const Parser = require('rss-parser');
const parser = new Parser({
  customFields: {
    item: ['contentSnippet', 'content:encoded']
  }
});

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

// Decode HTML entities
function decodeHtmlEntities(text) {
  const entities = {
    '&#8217;': "'",
    '&#8216;': "'",
    '&#8220;': '"',
    '&#8221;': '"',
    '&#8211;': '–',
    '&#8212;': '—',
    '&#x26;': '&',
    '&#38;': '&',
    '&quot;': '"',
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&apos;': "'"
  };
  
  return text.replace(/&#?\w+;/g, match => entities[match] || match);
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

let cache = { threats: [], zeroDays: [], lastUpdate: 0 };
const CACHE_TTL = 15 * 60 * 1000;

// Classify severity based on threat indicators in content
function classifyThreat(item) {
  const text = `${item.title} ${item.contentSnippet || ''}`.toLowerCase();
  
  // Critical indicators - ONLY truly severe, immediate threats
  const critical = [
    'zero-day exploit', 'zero day exploit', 'actively exploited in the wild',
    'ransomware attack', 'nation-state attack', 'supply chain compromise',
    'wormable vulnerability', 'mass exploitation', 'critical rce'
  ];
  
  // High severity indicators - serious threats, but more specific
  const high = [
    'remote code execution', 'unauthenticated rce',
    'privilege escalation to root', 'authentication bypass vulnerability',
    'sql injection vulnerability', 'major data breach',
    'widespread malware campaign', 'critical patch released',
    'actively exploited', 'exploit in the wild'
  ];
  
  // Medium severity indicators - real threats but contained/patchable
  const medium = [
    'vulnerability disclosed', 'security flaw', 'exploit available',
    'malware detected', 'trojan', 'phishing campaign',
    'unauthorized access', 'security breach', 'ddos attack',
    'botnet activity', 'credential theft', 'ransomware variant'
  ];
  
  // Low severity indicators - advisories, tips, general awareness
  const low = [
    'security update', 'patch available', 'advisory issued',
    'security recommendation', 'best practice', 'how to protect',
    'security tip', 'awareness campaign', 'warning issued',
    'vulnerability patched', 'fix released'
  ];
  
  // Check for critical (requires exact phrase match for stricter classification)
  if (critical.some(keyword => text.includes(keyword))) {
    return 'Critical';
  }
  
  // Check for high - but exclude if it's just about patches/fixes
  if (high.some(keyword => text.includes(keyword))) {
    // Downgrade if it's about a patch being available
    if (text.includes('patch') || text.includes('fix released') || text.includes('update available')) {
      return 'Medium';
    }
    return 'High';
  }
  
  // Check for CVE mentions - Medium by default (not all CVEs are critical)
  if (text.match(/cve[-–]?\d{4}[-–]?\d{4,7}/i)) {
    // Only High if explicitly mentioned as critical or actively exploited
    if (text.includes('critical') || text.includes('actively exploited')) {
      return 'High';
    }
    return 'Medium';
  }
  
  // Check for medium
  if (medium.some(keyword => text.includes(keyword))) {
    return 'Medium';
  }
  
  // Check for low
  if (low.some(keyword => text.includes(keyword))) {
    return 'Low';
  }
  
  // Default to Low for general news/informational content
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
      
      feed.items.slice(0, 10).forEach(item => {
        const title = item.title || '';
        const content = item.contentSnippet || '';
        const combinedText = `${title} ${content}`.toLowerCase();
        
        // Skip promotional/event content
        const skipKeywords = ['virtual event', 'sale', 'meetup', 'meet up'];
        if (skipKeywords.some(keyword => combinedText.includes(keyword))) {
          return; // Skip this item
        }
        
        // Skip items older than 7 days
        const itemDate = new Date(item.pubDate || item.isoDate);
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        if (itemDate < sevenDaysAgo) {
          return; // Skip this item
        }
        
        // Check for CVE (for zero-days)
        const cveMatch = title.match(/CVE[-–]?(\d{4}-\d{4,7})/i);
        if (cveMatch) {
          zeroDays.push({
            cve: `CVE-${cveMatch[1]}`,
            product: title.includes('Microsoft') ? 'Microsoft' : 
                     title.includes('Google') ? 'Google' :
                     title.includes('Apple') ? 'Apple' : 'Unknown',
            dateAdded: itemDate.toISOString().split('T')[0],
            source: sourceName,
            link: item.link
          });
        }
        
        // Add as threat (from RSS feeds)
        threats.push({
          id: `rss-${Buffer.from(item.link).toString('base64').slice(0, 10)}`,
          type: determineThreatType(item),
          severity: classifyThreat(item),
          summary: decodeHtmlEntities(title.slice(0, 150)),
          lastSeen: itemDate.toISOString(),
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
      
      // Classify based on tags and content - more conservative
      let severity = 'Low';
      const tags = (p.tags || []).join(' ').toLowerCase();
      const description = (p.description || '').toLowerCase();
      const combined = `${tags} ${description} ${p.name}`.toLowerCase();
      
      // Critical only for truly severe threats
      if ((combined.includes('critical') && combined.includes('exploit')) ||
          combined.includes('ransomware attack') || 
          combined.includes('zero-day') || 
          (combined.includes('apt') && combined.includes('campaign'))) {
        severity = 'Critical';
      } 
      // High for serious active threats
      else if ((combined.includes('exploit') && hasIPs) || 
               (combined.includes('malware') && combined.includes('campaign')) ||
               combined.includes('actively exploited')) {
        severity = 'High';
      } 
      // Medium for vulnerabilities and general threats
      else if (combined.includes('vulnerability') || 
               combined.includes('malicious') ||
               combined.includes('attack') || 
               hasIPs) {
        severity = 'Medium';
      }
      // Otherwise stays 'Low' for general intel/advisories

      threats.push({
        id: p.id,
        type: p.tags[0] || 'malware',
        severity: severity,
        summary: decodeHtmlEntities(p.name),
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

  // Sort threats by date (most recent first), not severity
  const sortedThreats = threats
    .sort((a, b) => {
      return new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime();
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