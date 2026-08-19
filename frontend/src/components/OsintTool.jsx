import { useState } from 'react';
import axios from 'axios';
import LoadingSpinner from './LoadingSpinner';

export default function OsintTool() {
    const [target, setTarget] = useState('');
    const [targetType, setTargetType] = useState('domain');
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState('');

    const getPlaceholder = () => {
        if (targetType === 'domain') return "e.g., netflix.com";
        if (targetType === 'ip') return "e.g., 8.8.8.8";
        return "e.g., target@example.com";
    };

    const runOsintScan = async () => {
        setLoading(true);
        setError('');
        setResults(null);

        // This ensures it works on both localhost and Vercel
        const API_BASE = import.meta.env.VITE_API_BASE_URL
            ? `${import.meta.env.VITE_API_BASE_URL}/api/osint`
            : 'http://127.0.0.1:8000/api/osint';

        try {
            const response = await axios.post(`${API_BASE}/scan`, {
                target: target.trim(),
                target_type: targetType
            });
            setResults(response.data);
        } catch (err) {
            setError(err.response?.data?.detail || 'An error occurred while fetching OSINT data.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl text-slate-100">
            <h2 className="text-2xl font-bold mb-2 text-white">Advanced OSINT Engine</h2>
            <p className="text-slate-400 mb-6 text-sm">Passive reconnaissance, dark web leaks, and infrastructure scraping.</p>

            {/* INPUT SECTION */}
            <div className="flex flex-col sm:flex-row gap-4 mb-6">
                <select
                    value={targetType}
                    onChange={(e) => setTargetType(e.target.value)}
                    className="p-3 border border-slate-800 rounded-lg focus:outline-none focus:border-purple-500 bg-slate-950 text-slate-100 font-semibold cursor-pointer"
                >
                    <option value="domain" className="bg-slate-900 text-slate-100">Website Domain</option>
                    <option value="ip" className="bg-slate-900 text-slate-100">IP Address</option>
                    <option value="email" className="bg-slate-900 text-slate-100">Email Address</option>
                </select>
                <input
                    type="text"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder={getPlaceholder()}
                    className="flex-1 p-3 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono"
                />
                <button
                    onClick={runOsintScan}
                    disabled={loading || !target}
                    className="px-8 py-3 bg-purple-600 text-white font-bold rounded-lg hover:bg-purple-700 disabled:opacity-50 transition-colors"
                >
                    {loading ? 'Gathering Intel...' : 'Launch OSINT'}
                </button>
            </div>

            {error && (
                <div className="p-4 bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg font-medium text-sm">
                    {error}
                </div>
            )}

            {loading && (
                <div className="my-12">
                    <LoadingSpinner text="Querying global threat databases and scraping metadata..." color="#9333ea" />
                </div>
            )}

            {/* RESULTS SECTION */}
            {results && !loading && (
                <div className="space-y-6">

                    {/* AUTOMATED REPORT */}
                    <div className="bg-slate-950 rounded-xl overflow-hidden shadow-lg border border-slate-800">
                        <div className="bg-slate-900 px-4 py-2.5 border-b border-slate-800 flex items-center gap-2">
                            <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
                            <div className="w-3 h-3 rounded-full bg-yellow-500/80"></div>
                            <div className="w-3 h-3 rounded-full bg-green-500/80"></div>
                            <span className="text-slate-400 text-xs font-mono ml-2">Automated_Briefing.md</span>
                        </div>
                        <pre className="p-5 text-emerald-400 font-mono text-sm overflow-x-auto whitespace-pre-wrap leading-relaxed">
                            {results.markdown_report}
                        </pre>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

                        {/* DEEP EMAIL BREACH ANALYTICS */}
                        {targetType === 'email' && (
                            <div className="col-span-1 md:col-span-2 space-y-4">
                                {/* New Phishing Heuristics Block */}
                                {results.heuristics && (
                                    <div className={`p-6 border rounded-xl ${results.heuristics.risk_level === 'High' ? 'bg-yellow-500/10 border-yellow-500/30' : 'bg-slate-900 border-slate-800'}`}>
                                        <h3 className={`text-xl font-black mb-3 ${results.heuristics.risk_level === 'High' ? 'text-yellow-400' : 'text-emerald-400'}`}>
                                            {results.heuristics.risk_level === 'High' ? '⚠️ Phishing Indicators Detected' : '✅ No Obvious Phishing Patterns'}
                                        </h3>
                                        {results.heuristics.warnings?.length > 0 && (
                                            <ul className="list-disc pl-5 text-sm text-yellow-300 space-y-1">
                                                {results.heuristics.warnings.map((warn, idx) => <li key={idx}>{warn}</li>)}
                                            </ul>
                                        )}
                                    </div>
                                )}

                                {/* Existing Breaches Block */}
                                {results.breaches && (
                                    <div className={`p-6 border rounded-xl ${results.breaches.exposed_data?.length > 0 ? 'bg-red-500/10 border-red-500/30' : 'bg-emerald-500/10 border-emerald-500/30'}`}>
                                        <h3 className={`text-xl font-black mb-3 ${results.breaches.exposed_data?.length > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                                            {results.breaches.exposed_data?.length > 0 ? '🚨 Sensitive Data Exposed in Leaks' : '✅ No Known Breaches Found'}
                                        </h3>
                                        {results.breaches.exposed_data?.length > 0 && (
                                            <div>
                                                <p className="text-slate-300 text-sm mb-3">The following data categories were compromised:</p>
                                                <div className="flex flex-wrap gap-2">
                                                    {results.breaches.exposed_data.map((item, idx) => (
                                                        <span key={idx} className="px-3 py-1 bg-red-500/20 text-red-300 border border-red-500/30 rounded font-bold text-sm">
                                                            {item}
                                                        </span>
                                                    ))}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>
                        )}

                        {/* WEB SCRAPER METADATA */}
                        {targetType === 'domain' && results.scraper?.status === 'success' && (
                            <div className="p-5 border border-slate-800 rounded-xl bg-slate-950 md:col-span-2">
                                <h3 className="text-lg font-bold mb-4 text-white flex items-center gap-2">
                                    🕷️ Live Web Scraper
                                </h3>
                                <div className="space-y-3">
                                    <div>
                                        <span className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Page Title</span>
                                        <p className="text-slate-200 font-medium bg-slate-900 p-3 border border-slate-800 rounded-lg">{results.scraper.title}</p>
                                    </div>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                            <span className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Server Technology</span>
                                            <p className="text-purple-400 font-mono text-sm bg-slate-900 p-2.5 border border-slate-800 rounded-lg block">{results.scraper.server}</p>
                                        </div>
                                        {results.whois?.status === 'success' && (
                                            <div>
                                                <span className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Domain Expiration</span>
                                                <p className="text-emerald-400 font-mono text-sm bg-slate-900 p-2.5 border border-slate-800 rounded-lg block">{results.whois.expiration}</p>
                                            </div>
                                        )}
                                    </div>
                                    <div>
                                        <span className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Meta Description</span>
                                        <p className="text-slate-300 text-sm bg-slate-900 p-3 border border-slate-800 rounded-lg italic">{results.scraper.description}</p>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* THREAT INTELLIGENCE SCORING */}
                        {(targetType === 'ip' || targetType === 'domain') && (
                            <div className="p-5 border border-slate-800 rounded-xl bg-slate-950 md:col-span-2">
                                <h3 className="text-lg font-bold mb-4 text-white flex items-center gap-2">
                                    🛡️ Threat Reputation
                                </h3>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {/* ThreatFox Malware Hits */}
                                    {results.threatfox && (
                                        <div className={`p-4 rounded-lg border ${results.threatfox.malware_hits > 0 ? 'bg-red-500/10 border-red-500/30' : 'bg-slate-900 border-slate-800'}`}>
                                            <span className="text-xs text-slate-400 block uppercase font-semibold mb-1">Malware Indicators (ThreatFox)</span>
                                            <span className={`text-2xl font-black ${results.threatfox.malware_hits > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                                                {results.threatfox.malware_hits} Hits
                                            </span>
                                        </div>
                                    )}

                                    {/* AbuseIPDB Score (IP Only) */}
                                    {targetType === 'ip' && results.abuseipdb && results.abuseipdb.status === 'success' && (
                                        <div className={`p-4 rounded-lg border ${results.abuseipdb.abuse_score > 20 ? 'bg-orange-500/10 border-orange-500/30' : 'bg-slate-900 border-slate-800'}`}>
                                            <span className="text-xs text-slate-400 block uppercase font-semibold mb-1">Abuse Score (AbuseIPDB)</span>
                                            <span className={`text-2xl font-black ${results.abuseipdb.abuse_score > 20 ? 'text-orange-400' : 'text-emerald-400'}`}>
                                                {results.abuseipdb.abuse_score}/100
                                            </span>
                                            <p className="text-xs text-slate-500 mt-1">From {results.abuseipdb.total_reports} recent reports</p>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* ADVANCED IP GEOLOCATION */}
                        {targetType === 'ip' && results.geolocation?.status === 'success' && (
                            <div className="p-5 border border-slate-800 rounded-xl bg-slate-950 md:col-span-2">
                                <h3 className="text-lg font-bold mb-4 text-white flex items-center gap-2">
                                    📍 Network & Geolocation
                                </h3>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                    <div className="bg-slate-900 p-3.5 rounded-lg border border-slate-800">
                                        <span className="text-xs text-slate-400 block uppercase font-semibold">Location</span>
                                        <span className="font-bold text-slate-100 mt-1 block truncate">{results.geolocation.city}, {results.geolocation.country}</span>
                                    </div>
                                    <div className="bg-slate-900 p-3.5 rounded-lg border border-slate-800">
                                        <span className="text-xs text-slate-400 block uppercase font-semibold">ISP</span>
                                        <span className="font-bold text-slate-100 mt-1 block truncate">{results.geolocation.isp}</span>
                                    </div>
                                    <div className="bg-slate-900 p-3.5 rounded-lg border border-slate-800">
                                        <span className="text-xs text-slate-400 block uppercase font-semibold">ASN</span>
                                        <span className="font-bold text-slate-100 mt-1 block truncate">{results.geolocation.asn || "N/A"}</span>
                                    </div>
                                    <div className="bg-slate-900 p-3.5 rounded-lg border border-slate-800 flex flex-col justify-center gap-2">
                                        {results.geolocation.is_proxy ? (
                                            <span className="px-2 py-1 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-[10px] font-bold text-center uppercase tracking-wider">🛡️ Proxy/VPN Detected</span>
                                        ) : (
                                            <span className="px-2 py-1 bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded text-[10px] font-bold text-center uppercase tracking-wider">✅ No Proxy</span>
                                        )}
                                        {results.geolocation.is_hosting && (
                                            <span className="px-2 py-1 bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 rounded text-[10px] font-bold text-center uppercase tracking-wider">🏢 Datacenter IP</span>
                                        )}
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* DOMAIN DNS RECORDS */}
                        {targetType === 'domain' && results.dns?.status === 'success' && results.dns.records?.length > 0 && (
                            <div className="p-5 border border-slate-800 rounded-xl bg-slate-950">
                                <h3 className="text-lg font-bold mb-3 text-white flex items-center gap-2">
                                    🏢 Public DNS Records
                                </h3>
                                <div className="max-h-48 overflow-y-auto space-y-1.5 pr-2">
                                    {results.dns.records.map((rec, idx) => (
                                        <div key={idx} className="p-2.5 bg-slate-900 border border-slate-800 rounded text-xs text-slate-300 font-mono break-all shadow-sm">
                                            {rec}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* DOMAIN SUBDOMAINS */}
                        {targetType === 'domain' && results.subdomains && (
                            <div className="p-5 border border-slate-800 rounded-xl bg-slate-950">
                                <h3 className="text-lg font-bold mb-2 text-white flex items-center gap-2">
                                    🌐 Subdomain Enumeration
                                </h3>
                                <p className="text-sm text-slate-400 mb-3">Found {results.subdomains.count} unique subdomains.</p>
                                <div className="max-h-48 overflow-y-auto space-y-1.5 pr-2">
                                    {results.subdomains.subdomains?.map((sub, idx) => (
                                        <div key={idx} className="p-2 bg-slate-900 border border-slate-800 rounded text-sm text-slate-300 font-mono truncate shadow-sm">
                                            {sub}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* HISTORICAL WAYBACK URLS */}
                        {targetType === 'domain' && results.archived_urls && results.archived_urls.status === 'success' && (
                            <div className="p-5 border border-slate-800 rounded-xl bg-slate-950">
                                <h3 className="text-lg font-bold mb-2 text-white flex items-center gap-2">
                                    🏛️ Archived Endpoints
                                </h3>
                                <p className="text-sm text-slate-400 mb-3">Found {results.archived_urls.count} historical URLs via Wayback Machine.</p>
                                <div className="max-h-48 overflow-y-auto space-y-1.5 pr-2">
                                    {results.archived_urls.urls?.map((url, idx) => (
                                        <div key={idx} className="p-2 bg-slate-900 border border-slate-800 rounded text-xs text-slate-300 font-mono truncate shadow-sm hover:text-blue-400 cursor-pointer" onClick={() => window.open(url, '_blank')}>
                                            {url}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                    </div>
                </div>
            )}
        </div>
    );
}
