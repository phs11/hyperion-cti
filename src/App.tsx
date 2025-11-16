import { useState, useEffect } from 'react';
import axios from 'axios';
import { formatDistanceToNow } from 'date-fns';

interface Threat { id: string; type: string; severity: string; summary: string; lastSeen: string; sourceUrl: string; source: string; }
interface ZeroDay { cve: string; product: string; dateAdded: string; source: string; link: string; }

export default function App() {
  const [data, setData] = useState<{ threats: Threat[]; zeroDays: ZeroDay[] }>({ threats: [], zeroDays: [] });
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('All');

  const fetchData = async () => {
    setLoading(true);
    try {
      const res = await axios.get('/api/threats');
      console.log('API Response:', res.data);
      console.log('Threat severities:', res.data.threats.map((t: Threat) => ({ id: t.id, severity: t.severity })));
      setData(res.data);
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

  // Recalculate filtered threats whenever data or filter changes
  const filtered = data.threats.filter(t => {
    if (filter === 'All') return true;
    return t.severity === filter;
  });

  console.log('Current filter:', filter);
  console.log('Total threats:', data.threats.length);
  console.log('Filtered threats:', filtered.length);
  console.log('Filter breakdown:', {
    Critical: data.threats.filter((t: Threat) => t.severity === 'Critical').length,
    High: data.threats.filter((t: Threat) => t.severity === 'High').length,
    Medium: data.threats.filter((t: Threat) => t.severity === 'Medium').length,
    Low: data.threats.filter((t: Threat) => t.severity === 'Low').length,
  });

  // Get severity badge styling
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

  if (loading) return <div className="p-8 text-center">Loading...</div>;

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <h1 className="text-4xl font-bold mb-2">Hyperion Cyber Threat Intelligence</h1>
      <p className="text-gray-400 mb-6">Free, real-time, zero-budget</p>

      <div className="flex gap-4 mb-6">
        <select 
          value={filter}
          onChange={e => {
            console.log('Filter changed to:', e.target.value);
            setFilter(e.target.value);
          }} 
          className="p-2 bg-gray-800 rounded text-white border border-gray-700"
        >
          <option value="All">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <button onClick={fetchData} className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded transition">
          Refresh
        </button>
        <div className="ml-auto text-sm text-gray-400 flex items-center">
          Showing {filtered.length} of {data.threats.length} threats
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-8">
        <div>
          <h2 className="text-2xl mb-4">Live Threat Feed (Top 25)</h2>
          {filtered.length === 0 ? (
            <div className="p-4 bg-gray-800 rounded-lg text-gray-400">
              No threats found matching the selected filter.
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