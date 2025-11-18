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

// Validate API keys
console.log('[INIT] API Key Status:');
console.log(`  OTX: ${OTX_KEY ? 'Present (' + OTX_KEY.substring(0, 8) + '...)' : 'MISSING'}`);
console.log(`  VT: ${VT_KEY ? 'Present (' + VT_KEY.substring(0, 8) + '...)' : 'MISSING'}`);
console.log(`  AbuseIPDB: ${ABUSEIPDB_KEY ? 'Present (' + ABUSEIPDB_KEY.substring(0, 8) + '...)' : 'MISSING'}`);

if (!OTX_KEY || !VT_KEY || !ABUSEIPDB_KEY) {
  console.error('[INIT] Missing API keys - cannot proceed');
  exports.handler = async () => ({
    statusCode: 500,
    body: JSON.stringify({ error: 'Missing API keys' })
  });
  return;
}

// ========================================
// ENHANCED: Product Name Extraction
// ========================================
function extractProductFromDescription(description, cveId = '') {
  if (!description) return 'Unknown';
  
  // Remove common prefixes and noise words
  let cleaned = description
    .replace(/^(A|An|The)\s+/i, '')
    .replace(/vulnerability (in|within|affecting|found in)/gi, '')
    .replace(/security (flaw|issue|bug)/gi, '')
    .replace(/allows?\s+(remote|local)?\s*(attackers?|users?)/gi, '')
    .trim();
  
  // Pattern 1: "Vendor Product" (e.g., "Microsoft Windows", "Apache Tomcat", "Google Chrome")
  const vendorProductMatch = cleaned.match(/^([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})/);
  if (vendorProductMatch) {
    const product = vendorProductMatch[1].trim();
    // Filter out generic words
    if (!['Application', 'Software', 'System', 'Service'].includes(product.split(' ')[0])) {
      return product;
    }
  }
  
  // Pattern 2: "product_name version" (e.g., "linux kernel", "wordpress")
  const productVersionMatch = cleaned.match(/^([a-z][a-z0-9_-]+)\s+(?:version\s+)?[\d.]+/i);
  if (productVersionMatch) {
    return productVersionMatch[1].split(/[-_]/).map(w => 
      w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()
    ).join(' ');
  }
  
  // Pattern 3: First capitalized word or phrase (up to 3 words)
  const capitalizedMatch = cleaned.match(/^([A-Z][a-zA-Z0-9]*(?:\s+[A-Z][a-zA-Z0-9]*){0,2})/);
  if (capitalizedMatch) {
    return capitalizedMatch[1].trim();
  }
  
  // Pattern 4: Look for product names after common indicators
  const indicatorMatch = cleaned.match(/(?:in|for|affecting)\s+([A-Z][a-zA-Z0-9]+(?:\s+[A-Z][a-zA-Z0-9]+)?)/i);
  if (indicatorMatch) {
    return indicatorMatch[1].trim();
  }
  
  // Fallback: First word if it's capitalized
  const firstWord = cleaned.split(/\s+/)[0];
  if (firstWord && /^[A-Z]/.test(firstWord)) {
    return firstWord;
  }
  
  return 'Unknown';
}

// Decode HTML entities
function decodeHtmlEntities(text) {
  if (!text) return '';
  
  const entities = {
    '&#8217;': "'", '&#8216;': "'", '&#8220;': '"', '&#8221;': '"',
    '&#8211;': '–', '&#8212;': '—', '&#x26;': '&', '&#38;': '&',
    '&#xa;': ' ', '&#10;': ' ', '&#xA;': ' ',
    '&quot;': '"', '&amp;': '&', '&lt;': '<', '&gt;': '>', '&#124;': '|', '&apos;': "'"
  };
  
  let decoded = text.replace(/&#?[xX]?[0-9a-fA-F]+;/g, match => {
    const lower = match.toLowerCase();
    return entities[lower] || entities[match] || match;
  });
  
  decoded = decoded.replace(/\s+/g, ' ').trim();
  
  return decoded;
}

const RSS_FEEDS = [
  'https://www.wired.com/feed/category/security/latest/rss',
  'https://www.thehackernews.com/feeds/posts/default',
  'https://feeds.arstechnica.com/arstechnica/index/',
  'https://threatpost.com/feed/',
  'https://krebsonsecurity.com/feed/',
  'https://www.bleepingcomputer.com/feed/',
  'https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v',
  'https://www.cisa.gov/cybersecurity-advisories/all.xml',
  'https://isc.sans.edu/rssfeed.xml',
  'https://www.darkreading.com/rss.xml',
  'https://feeds.feedburner.com/darknethackers',
  'https://www.darkreading.com/rss/all.xml',
  'https://www.infosecurity-magazine.com/rss/news/',
  'https://nakedsecurity.sophos.com/feed/',
  'https://www.schneier.com/blog/index.rdf',
  'https://msrc.microsoft.com/update-guide/'
];

const MISP_FEEDS = [
  { url: 'http://reputation.alienvault.com/reputation.data', name: 'DShield Top Attackers', type: 'txt' },
  { url: 'https://www.spamhaus.org/drop/drop.txt', name: 'Spamhaus DROP', type: 'txt' },
  { url: 'https://threatfox.abuse.ch/export/csv/recent/', name: 'ThreatFox Recent', type: 'csv' }
];

let cache = { threats: [], zeroDays: [], lastUpdate: 0, ipEnrichmentCache: {} };
const CACHE_TTL = 15 * 60 * 1000;
const VT_RATE_LIMIT_DELAY = 15000;

// VT API with caching
let lastVTCall = 0;
async function getVTData(ip) {
  console.log(`[VT] Checking IP: ${ip}`);
  
  if (cache.ipEnrichmentCache[ip] && cache.ipEnrichmentCache[ip].vt !== undefined) {
    console.log(`[VT] Cache hit for ${ip}: ${cache.ipEnrichmentCache[ip].vt}`);
    return cache.ipEnrichmentCache[ip].vt;
  }

  const now = Date.now();
  const timeSinceLastCall = now - lastVTCall;
  if (timeSinceLastCall < VT_RATE_LIMIT_DELAY) {
    const waitTime = VT_RATE_LIMIT_DELAY - timeSinceLastCall;
    console.log(`[VT] Rate limiting: waiting ${waitTime}ms`);
    await new Promise(resolve => setTimeout(resolve, waitTime));
  }

  try {
    console.log(`[VT] Making API call for ${ip}`);
    lastVTCall = Date.now();
    const response = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: { 'x-apikey': VT_KEY },
      timeout: 5000
    });
    
    const malicious = response.data?.data?.attributes?.last_analysis_stats?.malicious || 0;
    console.log(`[VT] Success for ${ip}: ${malicious} malicious detections`);
    
    if (!cache.ipEnrichmentCache[ip]) cache.ipEnrichmentCache[ip] = {};
    cache.ipEnrichmentCache[ip].vt = malicious;
    
    return malicious;
  } catch (e) {
    console.error(`[VT] Error for ${ip}:`, {
      message: e.message,
      status: e.response?.status
    });
    return 0;
  }
}

async function getAbuseIPDBData(ip) {
  console.log(`[AbuseIPDB] Checking IP: ${ip}`);
  
  if (cache.ipEnrichmentCache[ip] && cache.ipEnrichmentCache[ip].abuse !== undefined) {
    console.log(`[AbuseIPDB] Cache hit for ${ip}: ${cache.ipEnrichmentCache[ip].abuse}%`);
    return cache.ipEnrichmentCache[ip].abuse;
  }

  try {
    console.log(`[AbuseIPDB] Making API call for ${ip}`);
    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: { Key: ABUSEIPDB_KEY },
      timeout: 5000
    });
    
    const score = response.data?.data?.abuseConfidenceScore || 0;
    console.log(`[AbuseIPDB] Success for ${ip}: ${score}% confidence`);
    
    if (!cache.ipEnrichmentCache[ip]) cache.ipEnrichmentCache[ip] = {};
    cache.ipEnrichmentCache[ip].abuse = score;
    
    return score;
  } catch (e) {
    console.error(`[AbuseIPDB] Error for ${ip}:`, {
      message: e.message,
      status: e.response?.status
    });
    return 0;
  }
}

function classifyThreat(item) {
  const text = `${item.title} ${item.contentSnippet || ''}`.toLowerCase();
  
  const critical = [
    'zero-day exploit', 'zero day exploit', 'actively exploited in the wild',
    'ransomware attack', 'nation-state attack', 'supply chain compromise',
    'wormable vulnerability', 'mass exploitation', 'critical rce'
  ];
  
  const high = [
    'remote code execution', 'unauthenticated rce',
    'privilege escalation to root', 'authentication bypass vulnerability',
    'sql injection vulnerability', 'major data breach',
    'widespread malware campaign', 'critical patch released',
    'actively exploited', 'exploit in the wild'
  ];
  
  const medium = [
    'vulnerability disclosed', 'security flaw', 'exploit available',
    'malware detected', 'trojan', 'phishing campaign',
    'unauthorized access', 'security breach', 'ddos attack',
    'botnet activity', 'credential theft', 'ransomware variant'
  ];
  
  const low = [
    'security update', 'patch available', 'advisory issued',
    'security recommendation', 'best practice', 'how to protect',
    'security tip', 'awareness campaign', 'warning issued',
    'vulnerability patched', 'fix released'
  ];
  
  if (critical.some(keyword => text.includes(keyword))) return 'Critical';
  
  if (high.some(keyword => text.includes(keyword))) {
    if (text.includes('patch') || text.includes('fix released') || text.includes('update available')) {
      return 'Medium';
    }
    return 'High';
  }
  
  if (text.match(/cve[-–]?\d{4}[-–]?\d{4,7}/i)) {
    if (text.includes('critical') || text.includes('actively exploited')) {
      return 'High';
    }
    return 'Medium';
  }
  
  if (medium.some(keyword => text.includes(keyword))) return 'Medium';
  if (low.some(keyword => text.includes(keyword))) return 'Low';
  
  return 'Low';
}

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

function extractFirstIP(indicators) {
  if (!indicators || !Array.isArray(indicators)) {
    console.log('[IP Extract] No indicators array');
    return null;
  }

  console.log(`[IP Extract] Checking ${indicators.length} indicators`);

  indicators.slice(0, 5).forEach((ind, idx) => {
    console.log(`  [${idx}] type: "${ind.type}", indicator: "${ind.indicator}"`);
  });

  const ipTypes = ['IPv4', 'IPV4', 'ip', 'IP', 'IPv4 Address', 'ip-dst', 'ip-src'];
  const ipIndicator = indicators.find(i => 
    i.type && ipTypes.some(t => i.type.toLowerCase() === t.toLowerCase())
  );

  if (ipIndicator && ipIndicator.indicator) {
    const ip = ipIndicator.indicator.trim();
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
      console.log(`[IP Extract] Found IP via type: ${ip} (type: ${ipIndicator.type})`);
      return ip;
    }
  }

  const ipv4Regex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;
  for (const ind of indicators) {
    if (ind.indicator) {
      const match = ind.indicator.match(ipv4Regex);
      if (match) {
        const ip = match[1];
        console.log(`[IP Extract] Found IP via regex: ${ip} (type: ${ind.type})`);
        return ip;
      }
    }
  }

  console.log('[IP Extract] No IPv4 indicator found');
  return null;
}

function parseTxtFeed(data) {
  const lines = data.split('\n');
  const iocs = [];
  
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    
    const tokens = trimmed.split(/\s+/);
    let ioc = tokens[0];
    
    if (ioc.includes('#')) {
      ioc = ioc.split('#')[0];
    }
    
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/.test(ioc) || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(ioc)) {
      iocs.push(ioc);
    }
    
    if (iocs.length >= 3) break;
  }
  
  return iocs;
}

function parseCsvFeed(data) {
  const lines = data.split('\n');
  const iocs = [];
  
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    
    const columns = line.split(',');
    if (columns.length === 0) continue;
    
    const ioc = columns[0].replace(/"/g, '').trim();
    
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(ioc) || 
        /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(ioc) ||
        /^[a-f0-9]{32}$|^[a-f0-9]{64}$/i.test(ioc)) {
      iocs.push(ioc);
    }
    
    if (iocs.length >= 3) break;
  }
  
  return iocs;
}

async function fetchData() {
  const now = Date.now();
  if (cache.lastUpdate > now - CACHE_TTL) return cache;

  const zeroDays = [];
  const threats = [];
  const seenIOCs = new Set();

  // ========================================
  // ENHANCED: RSS Feeds - Search Title AND Content
  // ========================================
  for (const url of RSS_FEEDS) {
    try {
      const feed = await parser.parseURL(url);
      const sourceName = feed.title?.split(' - ')[0] || url.split('/')[2];
      
      feed.items.slice(0, 10).forEach(item => {
        const title = item.title || '';
        const content = item.contentSnippet || '';
        const fullText = `${title} ${content}`;
        const combinedText = fullText.toLowerCase();
        
        const skipKeywords = ['virtual event', 'sale', 'meetup', 'meet up'];
        if (skipKeywords.some(keyword => combinedText.includes(keyword))) return;
        
        const itemDate = new Date(item.pubDate || item.isoDate);
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        if (itemDate < sevenDaysAgo) return;
        
        // ENHANCED: Search full text for CVEs, not just title
        const cveMatch = fullText.match(/CVE[-–]?(\d{4}-\d{4,7})/i);
        if (cveMatch) {
          // ENHANCED: Better product extraction from context
          let product = 'Unknown';
          
          // Try to find product name near the CVE mention
          const cveContext = fullText.substring(
            Math.max(0, fullText.indexOf(cveMatch[0]) - 100),
            Math.min(fullText.length, fullText.indexOf(cveMatch[0]) + 100)
          );
          
          const productMatch = cveContext.match(/(?:in|for|affecting)\s+([A-Z][a-zA-Z0-9]+(?:\s+[A-Z][a-zA-Z0-9]+)?)/i);
          if (productMatch) {
            product = productMatch[1].trim();
          } else {
            // Fallback to title parsing
            if (title.includes('Microsoft')) product = 'Microsoft';
            else if (title.includes('Google')) product = 'Google';
            else if (title.includes('Apple')) product = 'Apple';
            else if (title.includes('Adobe')) product = 'Adobe';
            else if (title.includes('Oracle')) product = 'Oracle';
            else if (title.includes('Cisco')) product = 'Cisco';
            else {
              // Use the new extraction function
              product = extractProductFromDescription(title, cveMatch[0]);
            }
          }
          
          zeroDays.push({
            cve: `CVE-${cveMatch[1]}`,
            product: product,
            dateAdded: itemDate.toISOString().split('T')[0],
            source: sourceName,
            link: item.link
          });
        }
        
        let cleanTitle = title.slice(0, 150);
        cleanTitle = cleanTitle.replace(/&#xa;/gi, ' ').replace(/&#10;/g, ' ').replace(/&#xA;/g, ' ');
        cleanTitle = decodeHtmlEntities(cleanTitle);
        
        threats.push({
          id: `rss-${Buffer.from(item.link).toString('base64').slice(0, 10)}`,
          type: determineThreatType(item),
          severity: classifyThreat(item),
          summary: cleanTitle,
          lastSeen: itemDate.toISOString(),
          sourceUrl: item.link,
          source: sourceName
        });
      });
    } catch (e) {
      console.error(`Error parsing ${url}:`, e.message);
    }
  }

  // CISA KEV
  try {
    console.log('[CISA KEV] Fetching...');
    const kev = await axios.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { timeout: 5000 });
    console.log(`[CISA KEV] Found ${kev.data.vulnerabilities.length} vulnerabilities`);
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
    console.error('[CISA KEV] Error:', e.message);
  }

  // ========================================
  // ENHANCED: NVD with CVSS Scores
  // ========================================
  try {
    console.log('[NVD] Fetching recent HIGH/CRITICAL CVEs...');
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const today = new Date().toISOString();
    
    const nvd = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
      params: {
        pubStartDate: thirtyDaysAgo,
        pubEndDate: today
      },
      headers: {
        'User-Agent': 'Hyperion-CTI-Dashboard/1.0'
      },
      timeout: 10000
    });
    
    console.log(`[NVD] Received ${nvd.data.vulnerabilities?.length || 0} CVEs`);
    
    if (nvd.data.vulnerabilities) {
      const criticalCVEs = nvd.data.vulnerabilities
        .filter((v) => {
          const metrics = v.cve?.metrics?.cvssMetricV31?.[0] || v.cve?.metrics?.cvssMetricV30?.[0];
          const severity = metrics?.cvssData?.baseSeverity;
          return severity === 'HIGH' || severity === 'CRITICAL';
        })
        .slice(0, 10);
      
      console.log(`[NVD] Filtered to ${criticalCVEs.length} HIGH/CRITICAL CVEs`);
      
      criticalCVEs.forEach((v) => {
        const cve = v.cve;
        const description = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
        
        // ENHANCED: Use new product extraction function
        const productName = extractProductFromDescription(description, cve.id);
        
        // ENHANCED: Extract CVSS score
        const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
        const cvssScore = metrics?.cvssData?.baseScore?.toString() || null;
        
        zeroDays.push({
          cve: cve.id,
          product: productName,
          dateAdded: cve.published?.split('T')[0] || 'Unknown',
          cvssScore: cvssScore,
          source: 'NVD',
          link: `https://nvd.nist.gov/vuln/detail/${cve.id}`
        });
      });
    }
  } catch (e) {
    console.error('[NVD] Error:', {
      message: e.message,
      status: e.response?.status
    });
  }

  // VulnCheck KEV
  try {
    console.log('[VulnCheck] Fetching KEV data...');
    const vulncheck = await axios.get('https://api.vulncheck.com/v3/index/vulncheck-kev', {
      timeout: 5000
    });
    
    if (vulncheck.data?.data) {
      console.log(`[VulnCheck] Found ${vulncheck.data.data.length} exploited CVEs`);
      vulncheck.data.data.slice(0, 10).forEach((v) => {
        zeroDays.push({
          cve: v.cve || 'Unknown',
          product: v.vendorProject || v.product || 'Unknown',
          dateAdded: v.dateAdded?.split('T')[0] || 'Unknown',
          source: 'VulnCheck KEV',
          link: `https://nvd.nist.gov/vuln/detail/${v.cve}`
        });
      });
    }
  } catch (e) {
    console.error('[VulnCheck] Error:', e.message);
  }

  const uniqueZeroDays = [...new Map(zeroDays.map(z => [z.cve, z])).values()]
    .sort((a, b) => b.dateAdded.localeCompare(a.dateAdded))
    .slice(0, 25);

  // OTX Threats with IP Enrichment
  try {
    console.log('[OTX] Fetching pulses...');
    const otx = await axios.get('https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10', {
      headers: { 'X-OTX-API-KEY': OTX_KEY },
      timeout: 8000
    });
    
    console.log(`[OTX] Received ${otx.data.results.length} pulses`);

    for (const p of otx.data.results) {
      const indicators = p.indicators || [];
      console.log(`[OTX] Pulse "${p.name}" has ${indicators.length} indicators`);
      
      const ip = extractFirstIP(indicators);
      console.log(`[OTX] Extracted IP: ${ip || 'none'}`);
      
      let enrichment = '';
      let severity = 'Medium';

      if (ip && !seenIOCs.has(ip)) {
        seenIOCs.add(ip);
        console.log(`[OTX] Enriching IP: ${ip}`);
        
        const [vtMalicious, abuseScore] = await Promise.all([
          getVTData(ip),
          getAbuseIPDBData(ip)
        ]);
        
        enrichment = ` | ${ip} | VT: ${vtMalicious} malicious | Abuse: ${abuseScore}%`;
        
        if (abuseScore > 80 || vtMalicious > 10) {
          severity = 'Critical';
        } else if (abuseScore > 50 || vtMalicious > 3) {
          severity = 'High';
        } else {
          severity = 'Medium';
        }
      } else {
        enrichment = '';
        console.log(`[OTX] No IPv4 found or already enriched — skipping`);
      }

      const tags = (p.tags || []).join(' ').toLowerCase();
      const description = (p.description || '').toLowerCase();
      const combined = `${tags} ${description} ${p.name}`.toLowerCase();
      
      if ((combined.includes('critical') && combined.includes('exploit')) ||
          combined.includes('ransomware attack') || 
          combined.includes('zero-day')) {
        severity = 'Critical';
      }

      threats.push({
        id: p.id,
        type: p.tags[0] || 'malware',
        severity: severity,
        summary: decodeHtmlEntities(p.name) + enrichment,
        lastSeen: p.modified,
        sourceUrl: `https://otx.alienvault.com/pulse/${p.id}`,
        source: 'OTX'
      });
    }
    
    console.log(`[OTX] Successfully processed ${otx.data.results.length} pulses`);
  } catch (e) {
    console.error('[OTX] Error fetching pulses:', {
      message: e.message,
      status: e.response?.status
    });
  }

  // MISP Feeds
  for (const feed of MISP_FEEDS) {
    try {
      const response = await axios.get(feed.url, { timeout: 5000 });
      const iocs = feed.type === 'csv' ? parseCsvFeed(response.data) : parseTxtFeed(response.data);
      
      for (const ioc of iocs) {
        if (seenIOCs.has(ioc)) continue;
        seenIOCs.add(ioc);
        
        threats.push({
          id: `misp-${Buffer.from(ioc).toString('base64').slice(0, 10)}`,
          type: 'threat-intel',
          severity: 'High',
          summary: `IOC: ${ioc} from ${feed.name}`,
          lastSeen: new Date().toISOString(),
          sourceUrl: feed.url,
          source: 'MISP Feed'
        });
      }
    } catch (e) {
      console.error(`Error fetching MISP feed ${feed.name}:`, e.message);
    }
  }

  const sortedThreats = threats
    .sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime())
    .slice(0, 100);

  cache = { threats: sortedThreats, zeroDays: uniqueZeroDays, lastUpdate: now, ipEnrichmentCache: cache.ipEnrichmentCache };
  return cache;
}

exports.handler = async () => {
  try {
    const data = await fetchData();
    
    const diagnostics = {
      totalThreats: data.threats.length,
      otxThreats: data.threats.filter(t => t.source === 'OTX').length,
      mispThreats: data.threats.filter(t => t.source === 'MISP Feed').length,
      enrichedIPs: Object.keys(data.ipEnrichmentCache).length,
      totalCVEs: data.zeroDays.length,
      cvesWithCVSS: data.zeroDays.filter(z => z.cvssScore).length
    };
    
    console.log('[DIAGNOSTICS]', JSON.stringify(diagnostics));
    
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