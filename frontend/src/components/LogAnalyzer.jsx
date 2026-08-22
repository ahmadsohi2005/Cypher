import { useState, useRef } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { 
    FileText, 
    Upload, 
    Trash2, 
    ShieldAlert, 
    AlertTriangle, 
    Terminal, 
    Activity, 
    CheckCircle2, 
    Copy, 
    Check, 
    Filter, 
    Search, 
    AlertCircle,
    Zap,
    Server,
    Flame,
    Monitor
} from 'lucide-react';
import LoadingSpinner from './LoadingSpinner';
import { saveActivity } from '../utils/historyManager';

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

    windows: `2026-08-22 14:02:10 Event ID: 4625 Microsoft-Windows-Security-Auditing Audit Failure: An account failed to log on. Account Name: Administrator, Workstation Name: WIN-SRV01, Source Network Address: 192.168.1.180, Failure Reason: Unknown user name or bad password.
2026-08-22 14:02:12 Event ID: 4625 Microsoft-Windows-Security-Auditing Audit Failure: An account failed to log on. Account Name: Administrator, Workstation Name: WIN-SRV01, Source Network Address: 192.168.1.180, Failure Reason: Unknown user name or bad password.
2026-08-22 14:02:15 Event ID: 4625 Microsoft-Windows-Security-Auditing Audit Failure: An account failed to log on. Account Name: Administrator, Workstation Name: WIN-SRV01, Source Network Address: 192.168.1.180, Failure Reason: Unknown user name or bad password.
2026-08-22 14:05:00 Event ID: 4688 Microsoft-Windows-Security-Auditing A new process has been created. Creator Process Name: C:\\Windows\\System32\\cmd.exe, New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...
2026-08-22 14:06:22 Event ID: 7045 Service Control Manager A service was installed in the system. Service Name: RansomService, Service File Name: C:\\Users\\Public\\malware.exe, Service Type: user mode service
2026-08-22 14:07:01 Event ID: 1102 Microsoft-Windows-Eventlog The audit log was cleared by user: WIN-SRV01\\Attacker
2026-08-22 14:10:00 Application Error Event ID: 1000 Faulting application name: svchost.exe, version: 10.0.19041.1, time stamp: 0x5ee76cf7, Faulting module name: ntdll.dll, Exception code: 0xc0000005`,

    firewall: `Aug 19 12:00:01 edge-fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=198.51.100.4 DST=192.168.1.10 PROTO=TCP DPT=22
Aug 19 12:00:02 edge-fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=198.51.100.4 DST=192.168.1.10 PROTO=TCP DPT=80
Aug 19 12:00:03 edge-fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=198.51.100.4 DST=192.168.1.10 PROTO=TCP DPT=443
Aug 19 12:00:04 edge-fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=198.51.100.4 DST=192.168.1.10 PROTO=TCP DPT=3389`
};

export default function LogAnalyzer() {
    const [rawLogs, setRawLogs] = useState('');
    const [uploadedFileMeta, setUploadedFileMeta] = useState(null);
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState('');
    const [copiedKey, setCopiedKey] = useState(null);
    const [searchFilter, setSearchFilter] = useState('');
    const fileInputRef = useRef(null);

    const API_BASE = import.meta.env.VITE_API_BASE_URL
        ? `${import.meta.env.VITE_API_BASE_URL}/api/logs`
        : 'http://127.0.0.1:8000/api/logs';

    const copyToClipboard = (text, key) => {
        if (!text) return;
        navigator.clipboard.writeText(typeof text === 'object' ? JSON.stringify(text, null, 2) : text);
        setCopiedKey(key);
        setTimeout(() => setCopiedKey(null), 2000);
    };

    // Fast, non-blocking binary chunked Base64 encoder (prevents UI freeze on large 17k+ lines)
    const fastBase64Encode = (str) => {
        try {
            const bytes = new TextEncoder().encode(str);
            let binary = '';
            const len = bytes.byteLength;
            const chunkSize = 8192;
            for (let i = 0; i < len; i += chunkSize) {
                binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + chunkSize, len)));
            }
            return btoa(binary);
        } catch {
            return btoa(unescape(encodeURIComponent(str.slice(0, 50000))));
        }
    };

    const handleAnalyze = async () => {
        if (!rawLogs.trim()) return;
        setLoading(true);
        setError('');
        setResults(null);

        try {
            // Encode logs to pass cloud firewalls smoothly without blocking the thread
            const encodedLogs = fastBase64Encode(rawLogs);

            const res = await axios.post(`${API_BASE}/analyze`, {
                raw_logs: encodedLogs,
                is_encoded: true
            });
            setResults(res.data);
            saveActivity({
                module: 'Log Analyzer',
                action: 'Log Analysis',
                target: uploadedFileMeta ? `${uploadedFileMeta.name} (${res.data.summary.total_lines} lines)` : `Stream (${res.data.summary.total_lines} lines)`,
                summary: `Analyzed logs: found ${res.data.summary.total_threats} threat(s) and ${res.data.summary.brute_force_alerts?.length || 0} brute-force attempt(s)`,
                fullResult: res.data
            });
        } catch (err) {
            setError(err.response?.data?.detail || 'Log analysis failed or backend is unreachable.');
        } finally {
            setLoading(false);
        }
    };

    const handleFileUpload = (e) => {
        const file = e.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (event) => {
                const text = event.target.result;
                setRawLogs(text);
                const lines = text.split('\n').length;
                const sizeKb = (file.size / 1024).toFixed(1);
                setUploadedFileMeta({
                    name: file.name,
                    size: `${sizeKb} KB`,
                    lines: lines
                });
            };
            reader.readAsText(file);
        }
    };

    const handleClear = () => {
        setRawLogs('');
        setUploadedFileMeta(null);
        if (fileInputRef.current) fileInputRef.current.value = '';
    };

    const lineCount = rawLogs.trim() ? rawLogs.trim().split('\n').length : 0;

    const filteredEvents = results?.flagged_events?.filter(event => {
        if (!searchFilter) return true;
        const query = searchFilter.toLowerCase();
        return event.threat?.toLowerCase().includes(query) ||
               event.raw?.toLowerCase().includes(query) ||
               event.severity?.toLowerCase().includes(query) ||
               event.category?.toLowerCase().includes(query) ||
               String(event.line).includes(query);
    }) || [];

    return (
        <div className="w-full bg-slate-900/60 backdrop-blur-xl border border-slate-800/80 rounded-2xl shadow-[0_0_50px_rgba(0,0,0,0.5)] p-6 sm:p-8 text-slate-200 relative overflow-hidden">
            {/* Ambient Background Glow */}
            <div className="absolute top-0 right-0 w-96 h-96 bg-emerald-600/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>

            {/* Top Tactical Header */}
            <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 mb-8 border-b border-slate-800/80">
                <div className="flex items-center gap-4">
                    <div className="p-3 bg-emerald-500/10 rounded-xl border border-emerald-500/30 shadow-[0_0_20px_rgba(16,185,129,0.2)]">
                        <FileText className="w-7 h-7 text-emerald-400" />
                    </div>
                    <div>
                        <div className="flex items-center gap-2 mb-1">
                            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-wide">Log Analyzer & SIEM</h2>
                            <span className="px-2 py-0.5 bg-emerald-950/60 border border-emerald-500/40 text-emerald-400 text-[10px] font-mono font-semibold rounded tracking-wider uppercase">
                                [SIEM_TRIAGE_CORE]
                            </span>
                        </div>
                        <p className="text-sm text-slate-400 font-mono">
                            Heuristic regex signature matching, brute-force correlation, and attack telemetry parser.
                        </p>
                    </div>
                </div>

                <div className="flex items-center gap-2 self-start md:self-auto bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800 text-xs font-mono text-slate-400">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span>INGEST_PIPELINE: ACTIVE (UP TO 25MB)</span>
                </div>
            </div>

            {/* Presets & Ingestion Action Bar */}
            <div className="relative z-10 bg-slate-950/60 border border-slate-800/80 rounded-2xl p-5 sm:p-6 mb-8 shadow-inner">
                <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
                    <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                            <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                            Sample Ingestion:
                        </span>
                        <button
                            onClick={() => { setRawLogs(PRESETS.web); setUploadedFileMeta(null); }}
                            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white text-xs font-mono rounded-lg border border-slate-800 transition-colors"
                        >
                            Web Attacks (SQLi/XSS)
                        </button>
                        <button
                            onClick={() => { setRawLogs(PRESETS.auth); setUploadedFileMeta(null); }}
                            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white text-xs font-mono rounded-lg border border-slate-800 transition-colors"
                        >
                            SSH Brute Force
                        </button>
                        <button
                            onClick={() => { setRawLogs(PRESETS.windows); setUploadedFileMeta(null); }}
                            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white text-xs font-mono rounded-lg border border-slate-800 transition-colors flex items-center gap-1.5"
                        >
                            <Monitor className="w-3 h-3 text-cyan-400" />
                            Windows Event Logs
                        </button>
                        <button
                            onClick={() => { setRawLogs(PRESETS.firewall); setUploadedFileMeta(null); }}
                            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white text-xs font-mono rounded-lg border border-slate-800 transition-colors"
                        >
                            Firewall Port Drops
                        </button>
                    </div>

                    <div className="flex items-center gap-2">
                        <label className="cursor-pointer px-3.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-xs font-mono font-medium rounded-lg text-slate-300 border border-slate-700 hover:border-slate-600 transition-all flex items-center gap-2 shadow-sm">
                            <Upload className="w-3.5 h-3.5 text-emerald-400" />
                            <span>Upload File</span>
                            <input ref={fileInputRef} type="file" accept=".log,.txt,.csv,.xml,.evtx" onChange={handleFileUpload} className="hidden" />
                        </label>
                        {rawLogs && (
                            <button
                                onClick={handleClear}
                                className="px-3 py-1.5 bg-slate-900 hover:bg-red-950/40 text-slate-400 hover:text-red-300 text-xs font-mono rounded-lg border border-slate-800 hover:border-red-500/40 transition-colors flex items-center gap-1.5"
                                title="Clear Editor"
                            >
                                <Trash2 className="w-3.5 h-3.5" />
                                <span>Clear</span>
                            </button>
                        )}
                    </div>
                </div>

                {/* Uploaded File Status Pill */}
                {uploadedFileMeta && (
                    <div className="mb-3 px-3.5 py-2 bg-emerald-950/30 border border-emerald-500/30 rounded-xl flex items-center justify-between text-xs font-mono text-emerald-300">
                        <div className="flex items-center gap-2">
                            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                            <span>Loaded File: <strong>{uploadedFileMeta.name}</strong> ({uploadedFileMeta.size} • {uploadedFileMeta.lines.toLocaleString()} lines)</span>
                        </div>
                        <span className="text-[10px] bg-emerald-500/20 px-2 py-0.5 rounded font-bold">READY TO ANALYZE</span>
                    </div>
                )}

                {/* Raw Log Input Textarea */}
                <div className="relative mb-4">
                    <textarea
                        value={rawLogs}
                        onChange={(e) => setRawLogs(e.target.value)}
                        placeholder="Paste raw log lines (Windows Events / Nginx / Apache / SSH / Syslog / UFW) or upload a .log file..."
                        rows={7}
                        className="w-full p-4 bg-slate-900/90 border border-slate-700/80 rounded-xl font-mono text-xs text-slate-200 placeholder-slate-500 focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 focus:outline-none scrollbar-thin scrollbar-thumb-slate-800 transition-all leading-relaxed"
                    />
                    <div className="absolute bottom-3 right-3 text-[11px] font-mono text-slate-500 bg-slate-950/80 px-2 py-0.5 rounded border border-slate-800">
                        {lineCount.toLocaleString()} lines
                    </div>
                </div>

                <button
                    onClick={handleAnalyze}
                    disabled={loading || !rawLogs.trim()}
                    className="w-full py-3.5 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-xl shadow-[0_0_25px_rgba(16,185,129,0.3)] disabled:opacity-50 disabled:shadow-none transition-all flex items-center justify-center gap-2 font-mono text-sm"
                >
                    <Zap className="w-4 h-4" />
                    {loading ? 'Correlating and Triaging Security Events...' : 'Execute SIEM Analysis'}
                </button>
            </div>

            {/* Error Message */}
            {error && (
                <div className="relative z-10 p-4 bg-red-950/40 border border-red-500/40 text-red-300 rounded-xl font-medium text-sm mb-6 flex items-start gap-3 shadow-lg font-mono">
                    <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                    <div>
                        <span className="font-bold text-red-200 block">ANALYZER_ERROR:</span>
                        <span>{error}</span>
                    </div>
                </div>
            )}

            {/* Loading Indicator */}
            {loading && (
                <div className="relative z-10 my-10">
                    <LoadingSpinner text="Scanning regex signatures, evaluating brute force thresholds & categorizing IP sources..." color="#10b981" />
                </div>
            )}

            {/* Results Dashboard */}
            {results && !loading && (
                <motion.div
                    initial={{ opacity: 0, y: 15 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.25 }}
                    className="relative z-10 space-y-6"
                >
                    {/* SIEM Threat Metric Counters */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <div className="p-5 bg-slate-950/80 border border-slate-800 rounded-2xl">
                            <span className="text-xs uppercase font-mono text-slate-400 block mb-1">Total Ingested Lines</span>
                            <span className="text-3xl font-bold text-white font-mono">{results.summary.total_lines}</span>
                        </div>
                        <div className={`p-5 border rounded-2xl ${
                            results.summary.total_threats > 0
                                ? 'bg-red-950/30 border-red-500/40 shadow-[0_0_25px_rgba(239,68,68,0.15)]'
                                : 'bg-slate-950/80 border-slate-800'
                        }`}>
                            <span className="text-xs uppercase font-mono text-slate-400 block mb-1">Flagged Threat Signatures</span>
                            <span className={`text-3xl font-bold font-mono ${results.summary.total_threats > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                                {results.summary.total_threats}
                            </span>
                        </div>
                        <div className={`p-5 border rounded-2xl ${
                            results.summary.brute_force_alerts?.length > 0
                                ? 'bg-amber-950/30 border-amber-500/40 shadow-[0_0_25px_rgba(245,158,11,0.15)]'
                                : 'bg-slate-950/80 border-slate-800'
                        }`}>
                            <span className="text-xs uppercase font-mono text-slate-400 block mb-1">Brute-Force Anomaly Triggers</span>
                            <span className={`text-3xl font-bold font-mono ${results.summary.brute_force_alerts?.length > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
                                {results.summary.brute_force_alerts?.length || 0}
                            </span>
                        </div>
                    </div>

                    {/* Brute Force Anomaly Banner */}
                    {results.summary.brute_force_alerts?.length > 0 && (
                        <div className="p-5 bg-amber-950/30 border border-amber-500/40 rounded-2xl shadow-xl">
                            <div className="flex items-center gap-2 mb-3">
                                <Flame className="w-5 h-5 text-amber-400" />
                                <h4 className="text-sm font-bold text-amber-400 uppercase tracking-wider font-mono">Authentication Anomaly Alert</h4>
                            </div>
                            <div className="space-y-2">
                                {results.summary.brute_force_alerts.map((alert, idx) => (
                                    <div key={idx} className="p-3 bg-slate-900/90 rounded-xl border border-amber-500/20 text-xs font-mono text-amber-200 flex items-center justify-between">
                                        <div>
                                            Host <span className="font-bold underline text-white">{alert.ip}</span> generated {alert.failed_attempts} failed login attempts ({alert.assessment}).
                                        </div>
                                        <button
                                            onClick={() => copyToClipboard(alert.ip, `bf-ip-${idx}`)}
                                            className="text-slate-400 hover:text-white ml-2"
                                            title="Copy IP"
                                        >
                                            {copiedKey === `bf-ip-${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                                        </button>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Offending IPs and Signatures Breakdown */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Top Source IPs */}
                        <div className="p-6 bg-slate-950/80 border border-slate-800 rounded-2xl">
                            <div className="flex items-center justify-between mb-4">
                                <h4 className="text-base font-bold text-white font-mono flex items-center gap-2">
                                    <Server className="w-4 h-4 text-emerald-400" />
                                    Top Offending Source IPs
                                </h4>
                                <span className="text-xs font-mono text-slate-500">{results.summary.top_source_ips.length} IPs</span>
                            </div>
                            <div className="space-y-2 max-h-52 overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-slate-800">
                                {results.summary.top_source_ips.length > 0 ? (
                                    results.summary.top_source_ips.map((item, idx) => (
                                        <div key={idx} className="flex justify-between items-center p-3 bg-slate-900/90 rounded-xl border border-slate-800 font-mono text-xs">
                                            <div className="flex items-center gap-2">
                                                <span className="w-2 h-2 rounded-full bg-red-400"></span>
                                                <span className="text-white font-semibold">{item.ip}</span>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <span className="px-2 py-0.5 bg-red-500/10 text-red-300 border border-red-500/20 rounded text-[11px] font-bold">
                                                    {item.count} events
                                                </span>
                                                <button
                                                    onClick={() => copyToClipboard(item.ip, `ip-${idx}`)}
                                                    className="text-slate-500 hover:text-white"
                                                    title="Copy IP"
                                                >
                                                    {copiedKey === `ip-${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                                                </button>
                                            </div>
                                        </div>
                                    ))
                                ) : (
                                    <span className="text-xs text-slate-500 font-mono italic">No distinct source IPs identified</span>
                                )}
                            </div>
                        </div>

                        {/* Detected Threat Signatures */}
                        <div className="p-6 bg-slate-950/80 border border-slate-800 rounded-2xl">
                            <div className="flex items-center justify-between mb-4">
                                <h4 className="text-base font-bold text-white font-mono flex items-center gap-2">
                                    <ShieldAlert className="w-4 h-4 text-emerald-400" />
                                    Detected Attack Signatures
                                </h4>
                                <span className="text-xs font-mono text-slate-500">{Object.keys(results.summary.threat_distribution).length} Signatures</span>
                            </div>
                            <div className="space-y-2 max-h-52 overflow-y-auto pr-1 scrollbar-thin scrollbar-thumb-slate-800">
                                {Object.entries(results.summary.threat_distribution).length > 0 ? (
                                    Object.entries(results.summary.threat_distribution).map(([threat, count], idx) => (
                                        <div key={idx} className="flex justify-between items-center p-3 bg-slate-900/90 rounded-xl border border-slate-800 text-xs">
                                            <span className="text-red-300 font-mono font-medium">{threat}</span>
                                            <span className="font-mono text-red-400 font-bold bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded">
                                                {count} matches
                                            </span>
                                        </div>
                                    ))
                                ) : (
                                    <span className="text-xs text-slate-500 font-mono italic">No known attack signatures triggered</span>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Triaged Security Events Stream */}
                    <div className="p-6 bg-slate-950/80 border border-slate-800 rounded-2xl shadow-xl">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                            <div className="flex items-center gap-2">
                                <Activity className="w-5 h-5 text-emerald-400" />
                                <h4 className="text-base font-bold text-white font-mono">Triaged Security Event Feed</h4>
                            </div>
                            <div className="relative w-full sm:w-64">
                                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                    <Search className="w-3.5 h-3.5 text-slate-500" />
                                </div>
                                <input
                                    type="text"
                                    value={searchFilter}
                                    onChange={(e) => setSearchFilter(e.target.value)}
                                    placeholder="Filter triage feed..."
                                    className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                                />
                            </div>
                        </div>

                        <div className="space-y-2.5 max-h-96 overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-slate-800">
                            {filteredEvents.length > 0 ? (
                                filteredEvents.map((event, idx) => (
                                    <div key={idx} className="p-3.5 bg-slate-900/90 border border-slate-800 rounded-xl flex flex-col gap-1.5 text-xs hover:border-slate-700 transition-colors">
                                        <div className="flex justify-between items-center">
                                            <div className="flex items-center gap-2">
                                                <span className="px-2 py-0.5 bg-slate-950 border border-slate-800 text-slate-400 font-mono font-bold rounded text-[10px]">
                                                    LINE {event.line}
                                                </span>
                                                <span className="font-bold text-red-400 font-mono">{event.threat}</span>
                                            </div>
                                            <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                                                event.severity?.toLowerCase() === 'high' || event.severity?.toLowerCase() === 'critical'
                                                    ? 'bg-red-500/10 text-red-300 border-red-500/30'
                                                    : event.severity?.toLowerCase() === 'medium'
                                                        ? 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30'
                                                        : 'bg-blue-500/10 text-blue-300 border-blue-500/30'
                                            }`}>
                                                {event.severity}
                                            </span>
                                        </div>
                                        <div className="bg-slate-950/80 p-2 rounded-lg border border-slate-800/80 font-mono text-slate-300 text-[11px] break-all leading-relaxed">
                                            {event.raw}
                                        </div>
                                    </div>
                                ))
                            ) : (
                                <div className="text-center py-10 text-slate-500 font-mono text-xs">
                                    No events match the specified filter criteria.
                                </div>
                            )}
                        </div>
                    </div>
                </motion.div>
            )}
        </div>
    );
}
