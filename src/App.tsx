import { useState, useEffect } from 'react';
import axios from 'axios';
import { formatDistanceToNow } from 'date-fns';

interface Threat { id: string; type: string; severity: string; summary: string; lastSeen: string; sourceUrl: string; source: string; }
interface ZeroDay { cve: string; product: string; dateAdded: string; source: string; link: string; }

export default function App() {
  const [data, setData] = useState<{ threats: Threat[]; zeroDays: ZeroDay[] }>({ threats: [], zeroDays: [] });
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('All');
  const [typeFilter, setTypeFilter] = useState('All');
  const [sourceFilter, setSourceFilter] = useState('All');
  const [timeFilter, setTimeFilter] = useState('24h');
  const [topCount, setTopCount] = useState(25);
  const [currentTime, setCurrentTime] = useState(new Date());
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const res = await axios.get('/api/threats');
      setData(res.data);
      setLastUpdate(new Date());
    } catch (e) {
      console.error('Fetch error:', e);
      alert('Failed to load data');
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, 900000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Get unique types and sources from data
  const uniqueTypes = ['All', ...new Set(data.threats.map(t => t.type))];
  const uniqueSources = ['All', ...new Set(data.threats.map(t => t.source))];

  // Apply all filters and sort by date
  const filtered = data.threats
    .filter(t => {
      // Severity filter
      if (severityFilter !== 'All' && t.severity !== severityFilter) return false;
      
      // Type filter
      if (typeFilter !== 'All' && t.type !== typeFilter) return false;
      
      // Source filter
      if (sourceFilter !== 'All' && t.source !== sourceFilter) return false;
      
      // Time filter
      const threatTime = new Date(t.lastSeen).getTime();
      const now = Date.now();
      const timeRanges: Record<string, number> = {
        '1h': 3600000,
        '6h': 21600000,
        '24h': 86400000,
        '7d': 604800000
      };
      if (now - threatTime > timeRanges[timeFilter]) return false;
      
      return true;
    })
    .sort((a, b) => {
      // Sort by date, newest first
      return new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime();
    })
    .slice(0, topCount);

  const getSeverityStyle = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'bg-red-600 text-white';
      case 'High':
        return 'bg-orange-600 text-white';
      case 'Medium':
        return 'bg-yellow-500 text-gray-900';
      case 'Low':
        return 'bg-green-600 text-white';
      default:
        return 'bg-gray-600 text-white';
    }
  };

  const formatTimeEST = () => {
    return currentTime.toLocaleString('en-US', {
      timeZone: 'America/New_York',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true
    });
  };

  const formatDateEST = () => {
    return currentTime.toLocaleString('en-US', {
      timeZone: 'America/New_York',
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
  };

  const formatLastUpdate = () => {
    if (!lastUpdate) return 'Never';
    return lastUpdate.toLocaleString('en-US', {
      timeZone: 'America/New_York',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true
    });
  };

  const getTimeUntilNextUpdate = () => {
    if (!lastUpdate) return 'Soon';
    const nextUpdate = new Date(lastUpdate.getTime() + 900000);
    const diff = nextUpdate.getTime() - currentTime.getTime();
    
    if (diff <= 0) return 'Updating...';
    
    const minutes = Math.floor(diff / 60000);
    const seconds = Math.floor((diff % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
  };

  if (loading) return <div className="p-8 text-center">Loading...</div>;

  return (
    <div className="min-h-screen bg-gray-900 text-white p-4 md:p-6">
      {/* Header - Mobile Responsive */}
      <div className="flex flex-col md:flex-row md:justify-between md:items-start mb-6 gap-4">
        <div>
          <h1 className="text-2xl md:text-4xl font-bold mb-2">Hyperion Cyber Threat Intelligence</h1>
          <p className="text-sm md:text-base text-gray-400">Free, real-time, zero-budget&nbsp;&nbsp;|&nbsp;&nbsp;Project by Omar Ahmadi</p>
        </div>
        <div className="text-left md:text-right">
          <div className="text-xl md:text-2xl font-mono font-bold text-white">
            {formatTimeEST()}
          </div>
          <div className="text-xs md:text-sm text-gray-400 mt-1">
            {formatDateEST()} EST
          </div>
        </div>
      </div>

      {/* Filters - Mobile Responsive */}
      <div className="bg-gray-800 rounded-lg p-3 md:p-4 mb-6">
        <div className="flex flex-col gap-3">
          {/* First Row: Dropdowns */}
          <div className="flex flex-col sm:flex-row gap-2 sm:gap-3">
            {/* Type Filter */}
            <select 
              value={typeFilter}
              onChange={e => setTypeFilter(e.target.value)} 
              className="flex-1 px-3 py-2 bg-gray-700 rounded text-white border border-gray-600 text-sm"
            >
              {uniqueTypes.map(type => (
                <option key={type} value={type}>
                  {type === 'All' ? 'All Types' : type.charAt(0).toUpperCase() + type.slice(1).replace('-', ' ')}
                </option>
              ))}
            </select>

            {/* Severity Filter */}
            <select 
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)} 
              className="flex-1 px-3 py-2 bg-gray-700 rounded text-white border border-gray-600 text-sm"
            >
              <option value="All">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>

            {/* Source Filter */}
            <select 
              value={sourceFilter}
              onChange={e => setSourceFilter(e.target.value)} 
              className="flex-1 px-3 py-2 bg-gray-700 rounded text-white border border-gray-600 text-sm"
            >
              {uniqueSources.map(source => (
                <option key={source} value={source}>
                  {source === 'All' ? 'All Sources' : source}
                </option>
              ))}
            </select>
          </div>

          {/* Second Row: Time and Top Count Filters */}
          <div className="flex flex-col sm:flex-row gap-2 sm:gap-3 sm:justify-between">
            {/* Time Filter */}
            <div className="flex gap-1 bg-gray-700 rounded p-1">
              {['1h', '6h', '24h', '7d'].map(time => (
                <button
                  key={time}
                  onClick={() => setTimeFilter(time)}
                  className={`flex-1 px-2 sm:px-3 py-1 rounded text-xs sm:text-sm transition ${
                    timeFilter === time 
                      ? 'bg-cyan-500 text-gray-900 font-semibold' 
                      : 'text-gray-300 hover:text-white'
                  }`}
                >
                  {time}
                </button>
              ))}
            </div>

            {/* Top Count Filter */}
            <div className="flex gap-1 bg-gray-700 rounded p-1">
              {[5, 10, 25].map(count => (
                <button
                  key={count}
                  onClick={() => setTopCount(count)}
                  className={`flex-1 px-2 sm:px-3 py-1 rounded text-xs sm:text-sm transition ${
                    topCount === count 
                      ? 'bg-white text-gray-900 font-semibold' 
                      : 'text-gray-300 hover:text-white'
                  }`}
                >
                  Top {count}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Refresh and Status Row */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mt-4 pt-4 border-t border-gray-700 gap-3">
          <button onClick={fetchData} className="w-full sm:w-auto px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded transition text-sm">
            Refresh Now
          </button>
          <div className="text-xs sm:text-sm text-gray-400 flex flex-col items-start sm:items-end">
            <div className="flex items-center gap-2">
              <span>Auto-refresh in:</span>
              <span className="font-mono text-gray-400">{getTimeUntilNextUpdate()}</span>
            </div>
            <div className="text-xs mt-1">Last updated: {formatLastUpdate()} EST</div>
          </div>
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-8">
        <div>
          <h2 className="text-2xl mb-4">Live Threat Feed (Top {topCount})</h2>
          {filtered.length === 0 ? (
            <div className="p-4 bg-gray-800 rounded-lg text-gray-400">
              No threats found matching the selected filters.
            </div>
          ) : (
            filtered.map((t, index) => (
              <div key={`${t.id}-${index}`} className="p-4 mb-3 bg-gray-800 rounded-lg hover:bg-gray-750 transition">
                <div className="flex justify-between items-start">
                  <span className="font-bold text-lg capitalize">{t.type.replace('-', ' ')}</span>
                  <span className={`px-3 py-1 text-xs font-semibold rounded-full ${getSeverityStyle(t.severity)}`}>
                    {t.severity}
                  </span>
                </div>
                <p className="text-sm mt-2 text-gray-300">{t.summary}</p>
                <div className="flex justify-between items-center mt-3">
                  <p className="text-xs text-gray-400">
                    {formatDistanceToNow(new Date(t.lastSeen))} ago
                  </p>
                  <a 
                    href={t.sourceUrl} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:text-blue-300 text-xs font-medium"
                  >
                    {t.source} →
                  </a>
                </div>
              </div>
            ))
          )}
        </div>

        <div>
          <h2 className="text-2xl mb-4">Exploited Zero-Days</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-gray-700">
                <tr>
                  <th className="text-left p-2">CVE</th>
                  <th className="text-left p-2">Product</th>
                  <th className="text-left p-2">Date</th>
                  <th className="text-left p-2">Source</th>
                </tr>
              </thead>
              <tbody>
                {data.zeroDays.map(z => (
                  <tr key={z.cve} className="border-b border-gray-800 hover:bg-gray-800 transition">
                    <td className="p-2">
                      <a 
                        href={z.link} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-blue-400 hover:text-blue-300 font-mono"
                      >
                        {z.cve}
                      </a>
                    </td>
                    <td className="p-2">{z.product}</td>
                    <td className="p-2 text-gray-400">{z.dateAdded}</td>
                    <td className="p-2 text-xs text-gray-500">{z.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}