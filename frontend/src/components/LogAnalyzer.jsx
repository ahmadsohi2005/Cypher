import { useState } from 'react';
import axios from 'axios';
import LoadingSpinner from './LoadingSpinner';

const PRESETS = {
    web: `192.168.1.105 - - [19/Aug/2026:10:14:22 +0000] "GET /index.php?id=1' UNION SELECT null, username, password FROM users-- HTTP/1.1" 200 4522 "-" "Mozilla/5.0"
10.0.0.45 - - [19/Aug/2026:10:14:25 +0000] "GET /../../etc/passwd HTTP/1.1" 404 231 "-" "sqlmap/1.6.4"
192.168.1.105 - - [19/Aug/2026:10:15:01 +0000] "GET /search?q=<script>alert('XSS')</script> HTTP/1.1" 200 1200 "-" "Mozilla/5.0"
172.16.0.22 - - [19/Aug/2026:10:15:10 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Nikto/2.1.6"
192.168.1.50 - - [19/Aug/2026:10:16:00 +0000] "GET /dashboard HTTP/1.1" 200 8921 "-" "Mozilla/5.0"`,

    auth: `Aug 19 11:02:10 secure-srv sshd[12450]: Failed password for root from 203.0.113.195 port 44210 ssh2
Aug 19 11:02:12 secure-srv sshd[12452]: Failed password for root from 203.0.113.195 port 44212 ssh2
Aug 19 11:02:15 secure-srv sshd[12455]: Failed password for invalid user admin from 203.0.113.195 port 44218 ssh2
Aug 19 11:02:18 secure-srv sshd[12458]: Failed password for invalid user test from 203.0.113.195 port 44222 ssh2
Aug 19 11:04:01 secure-srv sudo:   ahmad : TTY=pts/0 ; PWD=/home/ahmad ; USER=root ; COMMAND=/bin/cat /etc/shadow
Aug 19 11:05:00 secure-srv sshd[12500]: Accepted publickey for ahmad from 192.168.1.50 port 52140 ssh2`,

    firewall: `Aug 19 12:00:01 edge-fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=198.51.100.4 DST=192.168.1.10 PROTO=TCP DPT=22
Aug 19 12:00:02 edge-fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=198.51.100.4 DST=192.168.1.10 PROTO=TCP DPT=80
Aug 19 12:00:03 edge-fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=198.51.100.4 DST=192.168.1.10 PROTO=TCP DPT=443
Aug 19 12:00:04 edge-fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=198.51.100.4 DST=192.168.1.10 PROTO=TCP DPT=3389`
};

export default function LogAnalyzer() {
    const [rawLogs, setRawLogs] = useState('');
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState('');

   // Replace your current API_BASE logic with this:
    const BASE_URL = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "") || 'http://localhost:8000';
    const API_BASE = `${BASE_URL}/api/logs`;

const handleAnalyze = async () => {
    if (!rawLogs.trim()) return;
    setLoading(true);
    setError('');
    setResults(null);

    try {
        // 1. WAF BYPASS: Send logs to Python securely
        const encodedLogs = btoa(unescape(encodeURIComponent(rawLogs)));

        const res = await axios.post(`${API_BASE}/analyze`, {
            raw_logs: encodedLogs,
            is_encoded: true 
        });
        
        // 2. Update the UI with the raw, readable data
        setResults(res.data);

        // 3. WAF BYPASS FOR DATABASE: Encode the malicious strings before saving history
        const safeHistoryData = {
            ...res.data,
            flagged_events: res.data.flagged_events.map(evt => ({
                ...evt,
                // Base64 encode the raw string so the database firewall doesn't drop the insert
                raw: "[ENCODED_FOR_WAF_SAFETY] " + btoa(unescape(encodeURIComponent(evt.raw)))
            }))
        };

        // 4. Added 'await' to catch silent database rejections!
        await saveActivity({
            module: 'Log Analyzer',
            action: 'Log Analysis',
            target: `Stream (${res.data.summary.total_lines} lines)`,
            summary: `Analyzed logs: found ${res.data.summary.total_threats} threat(s) and ${res.data.summary.brute_force_alerts?.length || 0} brute-force attempt(s)`,
            fullResult: safeHistoryData
        });

    } catch (err) {
        console.error("Log Analysis Error:", err);
        setError(err.response?.data?.detail || err.message || 'Log analysis failed or backend is unreachable.');
    } finally {
        setLoading(false);
    }
};
    
    const handleFileUpload = (e) => {
        const file = e.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (event) => setRawLogs(event.target.result);
            reader.readAsText(file);
        }
    };

    return (
        <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-6 text-slate-200">
            <h2 className="text-2xl font-bold text-white mb-2">SOC Security Log Analyzer</h2>
            <p className="text-slate-400 text-sm mb-6">Analyze Web Server, Linux Authentication, and Firewall logs for attack signatures and anomalies.</p>

            {/* Presets & Upload Bar */}
            <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
                <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold uppercase text-slate-400">Load Sample:</span>
                    <button onClick={() => setRawLogs(PRESETS.web)} className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-xs rounded text-slate-200">Web Attacks</button>
                    <button onClick={() => setRawLogs(PRESETS.auth)} className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-xs rounded text-slate-200">SSH Brute Force</button>
                    <button onClick={() => setRawLogs(PRESETS.firewall)} className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-xs rounded text-slate-200">Firewall Drops</button>
                </div>

                <label className="cursor-pointer px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-medium rounded text-slate-300 border border-slate-700">
                    Upload .log file
                    <input type="file" accept=".log,.txt" onChange={handleFileUpload} className="hidden" />
                </label>
            </div>

            {/* Input Area */}
            <textarea
                value={rawLogs}
                onChange={(e) => setRawLogs(e.target.value)}
                placeholder="Paste raw log lines here or select a sample above..."
                rows={8}
                className="w-full p-4 bg-slate-950 border border-slate-800 rounded-lg font-mono text-xs text-slate-300 focus:outline-none focus:border-blue-500 mb-4"
            />

            <button
                onClick={handleAnalyze}
                disabled={loading || !rawLogs.trim()}
                className="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-lg disabled:opacity-50 transition-colors"
            >
                {loading ? 'Correlating and Triaging Logs...' : 'Analyze Log Stream'}
            </button>

            {error && (
                <div className="mt-6 p-4 bg-red-900/20 border border-red-500/30 text-red-400 rounded-lg text-sm">
                    {error}
                </div>
            )}

            {loading && (
                <div className="mt-8">
                    <LoadingSpinner text="Scanning regex signatures, brute force counters, and source IPs..." color="#3b82f6" />
                </div>
            )}

            {/* Results Dashboard */}
            {results && !loading && (
                <div className="mt-8 space-y-6">

                    {/* Threat Metric Counters */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg">
                            <span className="text-xs uppercase text-slate-500 block mb-1">Total Lines Processed</span>
                            <span className="text-2xl font-bold text-white font-mono">{results.summary.total_lines}</span>
                        </div>
                        <div className={`p-4 border rounded-lg ${results.summary.total_threats > 0 ? 'bg-red-950/20 border-red-500/30' : 'bg-slate-950 border-slate-800'}`}>
                            <span className="text-xs uppercase text-slate-500 block mb-1">Flagged Threat Events</span>
                            <span className={`text-2xl font-bold font-mono ${results.summary.total_threats > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                                {results.summary.total_threats}
                            </span>
                        </div>
                        <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg">
                            <span className="text-xs uppercase text-slate-500 block mb-1">Brute-Force Detections</span>
                            <span className="text-2xl font-bold text-amber-400 font-mono">
                                {results.summary.brute_force_alerts?.length || 0}
                            </span>
                        </div>
                    </div>

                    {/* Brute Force Warning Banner */}
                    {results.summary.brute_force_alerts?.length > 0 && (
                        <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                            <h4 className="text-sm font-bold text-amber-400 uppercase tracking-wider mb-2">⚠️ Authentication Anomaly Detected</h4>
                            {results.summary.brute_force_alerts.map((alert, idx) => (
                                <p key={idx} className="text-xs text-amber-200 font-mono">
                                    Host <span className="font-bold underline">{alert.ip}</span> generated {alert.failed_attempts} failed login attempts ({alert.assessment}).
                                </p>
                            ))}
                        </div>
                    )}

                    {/* Offending IPs and Categories */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg">
                            <h4 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">Top Offending Source IPs</h4>
                            <div className="space-y-2">
                                {results.summary.top_source_ips.map((item, idx) => (
                                    <div key={idx} className="flex justify-between items-center p-2 bg-slate-900 rounded font-mono text-xs">
                                        <span className="text-blue-400">{item.ip}</span>
                                        <span className="text-slate-400">{item.count} events</span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg">
                            <h4 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">Detected Threat Signatures</h4>
                            <div className="space-y-2">
                                {Object.entries(results.summary.threat_distribution).length > 0 ? (
                                    Object.entries(results.summary.threat_distribution).map(([threat, count], idx) => (
                                        <div key={idx} className="flex justify-between items-center p-2 bg-slate-900 rounded text-xs">
                                            <span className="text-red-300">{threat}</span>
                                            <span className="font-mono text-red-400 font-bold">{count}</span>
                                        </div>
                                    ))
                                ) : (
                                    <span className="text-xs text-slate-500 italic">No threat signatures triggered.</span>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Granular Triage Log Feed */}
                    <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg">
                        <h4 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">Triaged Security Events</h4>
                        <div className="space-y-2 max-h-80 overflow-y-auto pr-2">
                            {results.flagged_events.map((event, idx) => (
                                <div key={idx} className="p-3 bg-slate-900 border border-slate-800/80 rounded flex flex-col gap-1 text-xs">
                                    <div className="flex justify-between items-center">
                                        <span className="font-bold text-red-400 font-mono">Line {event.line}: {event.threat}</span>
                                        <span className="px-2 py-0.5 rounded text-[10px] bg-red-500/10 text-red-300 border border-red-500/20 font-mono">{event.severity}</span>
                                    </div>
                                    <span className="text-slate-400 font-mono break-all">{event.raw}</span>
                                </div>
                            ))}
                        </div>
                    </div>

                </div>
            )}
        </div>
    );
}
