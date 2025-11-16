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
      setData(res.data);
    } catch (e) {
      alert('Failed to load data');
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, 900000);
    return () => clearInterval(id);
  }, []);

  const filtered = data.threats.filter(t => filter === 'All' || t.severity === filter);

  if (loading) return <div className="p-8 text-center">Loading...</div>;

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <h1 className="text-4xl font-bold mb-2">Hyperion CTI</h1>
      <p className="text-gray-400 mb-6">Free, real-time, zero-budget</p>

      <div className="flex gap-4 mb-6">
        <select onChange={e => setFilter(e.target.value)} className="p-2 bg-gray-800 rounded">
          <option>All</option>
          <option>Critical</option>
          <option>High</option>
          <option>Medium</option>
        </select>
        <button onClick={fetchData} className="px-4 py-2 bg-blue-600 rounded">Refresh</button>
      </div>

      <div className="grid lg:grid-cols-2 gap-8">
        <div>
          <h2 className="text-2xl mb-4">Top 25 Live Threats</h2>
          {filtered.map(t => (
            <div key={t.id} className="p-4 mb-3 bg-gray-800 rounded-lg">
              <div className="flex justify-between">
                <span className="font-bold">{t.type}</span>
                <span className={`px-3 py-1 text-xs rounded-full ${t.severity === 'Critical' ? 'bg-red-600' : 'bg-orange-600'}`}>
                  {t.severity}
                </span>
              </div>
              <p className="text-sm mt-1">{t.summary}</p>
              <p className="text-xs text-gray-400">{formatDistanceToNow(new Date(t.lastSeen))} ago</p>
              <a href={t.sourceUrl} target="_blank" className="text-blue-400 text-xs">Source</a>
            </div>
          ))}
        </div>

        <div>
          <h2 className="text-2xl mb-4">Exploited Zero-Days</h2>
          <table className="w-full text-sm">
            <thead className="border-b border-gray-700">
              <tr><th className="text-left p-2">CVE</th><th>Product</th><th>Date</th><th>Source</th></tr>
            </thead>
            <tbody>
              {data.zeroDays.map(z => (
                <tr key={z.cve}>
                  <td className="p-2"><a href={z.link} target="_blank" className="text-blue-400">{z.cve}</a></td>
                  <td>{z.product}</td>
                  <td>{z.dateAdded}</td>
                  <td className="text-xs">{z.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
