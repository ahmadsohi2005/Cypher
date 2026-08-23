import { useState } from 'react';
import apiClient from '../utils/apiClient';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Search,
    Globe,
    Server,
    Mail,
    FileText,
    ShieldAlert,
    ShieldCheck,
    MapPin,
    Cpu,
    Copy,
    Check,
    ExternalLink,
    AlertCircle,
    Terminal,
    Zap,
    History,
    Network,
    Layers
} from 'lucide-react';
import LoadingSpinner from './LoadingSpinner';
import { saveActivity } from '../utils/historyManager';

const TARGET_TYPES = [
    { id: 'domain', label: 'Domain Recon', icon: Globe, placeholder: 'e.g., netflix.com or target-corp.org' },
    { id: 'ip', label: 'IP Intelligence', icon: Server, placeholder: 'e.g., 8.8.8.8 or 104.244.42.1' },
    { id: 'email', label: 'Email Breach Audit', icon: Mail, placeholder: 'e.g., admin@target-corp.org' }
];

export default function OsintTool() {
    const [target, setTarget] = useState('');
    const [targetType, setTargetType] = useState('domain');
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState('');
    const [copiedKey, setCopiedKey] = useState(null);

    const copyToClipboard = (text, key) => {
        if (!text) return;
        navigator.clipboard.writeText(typeof text === 'object' ? JSON.stringify(text, null, 2) : text);
        setCopiedKey(key);
        setTimeout(() => setCopiedKey(null), 2000);
    };

    const runOsintScan = async () => {
        if (!target.trim()) return;
        setLoading(true);
        setError('');
        setResults(null);

        try {
            const response = await apiClient.post('/api/osint/scan', {
                target: target.trim(),
                target_type: targetType
            });
            setResults(response.data);
            saveActivity({
                module: 'OSINT',
                action: `${targetType.charAt(0).toUpperCase() + targetType.slice(1)} Recon`,
                target: target.trim(),
                summary: response.data.breaches?.exposed_data?.length > 0
                    ? `Compromised leaks found: ${response.data.breaches.exposed_data.join(', ')}`
                    : response.data.threatfox?.malware_hits > 0
                        ? `Malware hits detected: ${response.data.threatfox.malware_hits}`
                        : 'Intel gathered successfully',
                fullResult: response.data
            });
        } catch (err) {
            setError(err.response?.data?.detail || 'An error occurred while gathering OSINT intelligence.');
        } finally {
            setLoading(false);
        }
    };

    const currentTypeObj = TARGET_TYPES.find(t => t.id === targetType) || TARGET_TYPES[0];

    return (
        <div className="w-full bg-slate-900/60 backdrop-blur-xl border border-slate-800/80 rounded-2xl shadow-[0_0_50px_rgba(0,0,0,0.5)] p-6 sm:p-8 text-slate-200 relative overflow-hidden">
            {/* Ambient Background Glow */}
            <div className="absolute top-0 right-0 w-96 h-96 bg-purple-600/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>

            {/* Top Tactical Header */}
            <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 mb-8 border-b border-slate-800/80">
                <div className="flex items-center gap-4">
                    <div className="p-3 bg-purple-500/10 rounded-xl border border-purple-500/30 shadow-[0_0_20px_rgba(168,85,247,0.2)]">
                        <Search className="w-7 h-7 text-purple-400" />
                    </div>
                    <div>
                        <div className="flex items-center gap-2 mb-1">
                            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-wide">OSINT Intelligence</h2>
                        </div>
                        <p className="text-sm text-slate-400 font-mono">
                            Passive reconnaissance, dark web credential breach audits, and infrastructure scraping.
                        </p>
                    </div>
                </div>

                <div className="flex items-center gap-2 self-start md:self-auto bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800 text-xs font-mono text-slate-400">
                    <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse"></span>
                    <span>STATUS: AGGREGATING</span>
                </div>
            </div>

            {/* Target Type Selector Pills */}
            <div className="relative z-10 grid grid-cols-1 sm:grid-cols-3 gap-3 mb-6">
                {TARGET_TYPES.map((type) => {
                    const Icon = type.icon;
                    const isActive = targetType === type.id;
                    return (
                        <button
                            key={type.id}
                            onClick={() => {
                                setTargetType(type.id);
                                setResults(null);
                                setError('');
                            }}
                            className={`flex items-center justify-center gap-2.5 p-3.5 rounded-xl font-medium text-sm transition-all duration-200 border ${isActive
                                ? 'bg-purple-600/20 text-purple-300 border-purple-500/60 shadow-[0_0_20px_rgba(168,85,247,0.25)] font-semibold'
                                : 'bg-slate-950/40 text-slate-400 border-slate-800/80 hover:bg-slate-800/60 hover:text-slate-200 hover:border-slate-700'
                                }`}
                        >
                            <Icon className={`w-4 h-4 ${isActive ? 'text-purple-400' : 'text-slate-500'}`} />
                            <span>{type.label}</span>
                        </button>
                    );
                })}
            </div>

            {/* Ingestion & Input Card Area */}
            <div className="relative z-10 bg-slate-950/60 border border-slate-800/80 rounded-2xl p-5 sm:p-6 mb-8 shadow-inner">
                <label className="block text-xs font-mono text-slate-400 uppercase tracking-wider mb-2">
                    Scope Target ({targetType.toUpperCase()})
                </label>
                <div className="flex flex-col sm:flex-row gap-3">
                    <div className="relative flex-1">
                        <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                            <currentTypeObj.icon className="w-4 h-4 text-slate-500" />
                        </div>
                        <input
                            type="text"
                            value={target}
                            onChange={(e) => setTarget(e.target.value)}
                            placeholder={currentTypeObj.placeholder}
                            className="w-full pl-10 pr-4 py-3 bg-slate-900/80 border border-slate-700/80 rounded-xl text-white font-mono text-sm placeholder-slate-500 focus:border-purple-500 focus:ring-1 focus:ring-purple-500 focus:outline-none transition-all"
                            onKeyDown={(e) => e.key === 'Enter' && runOsintScan()}
                        />
                    </div>
                    <button
                        onClick={runOsintScan}
                        disabled={loading || !target.trim()}
                        className="px-8 py-3 bg-purple-600 hover:bg-purple-500 text-white font-bold rounded-xl shadow-[0_0_25px_rgba(168,85,247,0.3)] disabled:opacity-50 disabled:shadow-none transition-all flex items-center justify-center gap-2 shrink-0 font-mono text-sm"
                    >
                        <Zap className="w-4 h-4" />
                        {loading ? 'Gathering Intel...' : 'Launch OSINT'}
                    </button>
                </div>
            </div>

            {/* Error Display */}
            {error && (
                <div className="relative z-10 p-4 bg-red-950/40 border border-red-500/40 text-red-300 rounded-xl font-medium text-sm mb-6 flex items-start gap-3 shadow-lg font-mono">
                    <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                    <div>
                        <span className="font-bold text-red-200 block">OSINT_ERROR:</span>
                        <span>{error}</span>
                    </div>
                </div>
            )}

            {/* Loading Indicator */}
            {loading && (
                <div className="relative z-10 my-10">
                    <LoadingSpinner text="Harvesting passive telemetry, dark web breach dumps & DNS trees..." color="#a855f7" />
                </div>
            )}

            {/* Results Section */}
            {results && !loading && (
                <motion.div
                    initial={{ opacity: 0, y: 15 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.25 }}
                    className="relative z-10 space-y-6"
                >
                    {/* AUTOMATED REPORT BRIEFING CARD */}
                    {results.markdown_report && (
                        <div className="bg-slate-950/90 rounded-2xl overflow-hidden shadow-2xl border border-slate-800">
                            <div className="bg-slate-900/90 px-5 py-3 border-b border-slate-800 flex items-center justify-between">
                                <div className="flex items-center gap-2.5">
                                    <div className="flex items-center gap-1.5">
                                        <div className="w-2.5 h-2.5 rounded-full bg-red-500/80"></div>
                                        <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/80"></div>
                                        <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80"></div>
                                    </div>
                                    <span className="text-slate-400 text-xs font-mono font-semibold ml-2">OSINT_Synthesized_Briefing.md</span>
                                </div>
                                <button
                                    onClick={() => copyToClipboard(results.markdown_report, 'report')}
                                    className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-mono transition-colors"
                                >
                                    {copiedKey === 'report' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                                    <span>{copiedKey === 'report' ? 'Copied' : 'Copy Brief'}</span>
                                </button>
                            </div>
                            <pre className="p-6 text-emerald-400 font-mono text-xs sm:text-sm overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-96 scrollbar-thin scrollbar-thumb-slate-800">
                                {results.markdown_report}
                            </pre>
                        </div>
                    )}

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* DEEP EMAIL BREACH ANALYTICS */}
                        {targetType === 'email' && (
                            <div className="col-span-1 md:col-span-2 space-y-6">
                                {/* Phishing Heuristics Block */}
                                {results.heuristics && (
                                    <div className={`p-6 border rounded-2xl ${results.heuristics.risk_level === 'High'
                                        ? 'bg-yellow-950/30 border-yellow-500/40 shadow-[0_0_20px_rgba(234,179,8,0.15)]'
                                        : 'bg-slate-950/80 border-slate-800'
                                        }`}>
                                        <div className="flex items-center justify-between mb-3">
                                            <h3 className={`text-lg font-bold font-mono ${results.heuristics.risk_level === 'High' ? 'text-yellow-400' : 'text-emerald-400'}`}>
                                                {results.heuristics.risk_level === 'High' ? '⚠️ Phishing Indicators Detected' : '✅ No Obvious Phishing Patterns'}
                                            </h3>
                                            <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold uppercase border ${results.heuristics.risk_level === 'High'
                                                ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                                                : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                                                }`}>
                                                RISK: {results.heuristics.risk_level}
                                            </span>
                                        </div>
                                        {results.heuristics.warnings?.length > 0 && (
                                            <ul className="space-y-1.5 mt-3">
                                                {results.heuristics.warnings.map((warn, idx) => (
                                                    <li key={idx} className="text-xs text-yellow-300 font-mono flex items-start gap-2 bg-yellow-950/20 p-2.5 rounded-lg border border-yellow-500/20">
                                                        <span>•</span>
                                                        <span>{warn}</span>
                                                    </li>
                                                ))}
                                            </ul>
                                        )}
                                    </div>
                                )}

                                {/* Breaches Block */}
                                {results.breaches && (
                                    <div className={`p-6 border rounded-2xl ${results.breaches.exposed_data?.length > 0
                                        ? 'bg-red-950/30 border-red-500/40 shadow-[0_0_20px_rgba(239,68,68,0.15)]'
                                        : 'bg-emerald-950/20 border-emerald-500/30'
                                        }`}>
                                        <div className="flex items-center justify-between mb-3">
                                            <h3 className={`text-lg font-bold font-mono ${results.breaches.exposed_data?.length > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                                                {results.breaches.exposed_data?.length > 0 ? '🚨 Sensitive Data Compromised in Leaks' : '✅ No Known Breaches Found'}
                                            </h3>
                                            <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold uppercase border ${results.breaches.exposed_data?.length > 0
                                                ? 'bg-red-500/10 text-red-400 border-red-500/30'
                                                : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                                                }`}>
                                                {results.breaches.exposed_data?.length > 0 ? 'COMPROMISED' : 'CLEAN'}
                                            </span>
                                        </div>
                                        {results.breaches.exposed_data?.length > 0 && (
                                            <div>
                                                <p className="text-slate-300 text-xs font-mono mb-3">Compromised identity and security categories:</p>
                                                <div className="flex flex-wrap gap-2">
                                                    {results.breaches.exposed_data.map((item, idx) => (
                                                        <span key={idx} className="px-3 py-1 bg-red-500/20 text-red-300 border border-red-500/40 rounded-lg font-mono font-bold text-xs">
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
                            <div className="p-6 border border-slate-800 rounded-2xl bg-slate-950/80 md:col-span-2">
                                <h3 className="text-base font-bold mb-4 text-white font-mono flex items-center gap-2">
                                    <Globe className="w-5 h-5 text-purple-400" />
                                    Live Infrastructure & Header Scrape
                                </h3>
                                <div className="space-y-3 font-mono text-xs">
                                    <div>
                                        <span className="block text-slate-400 uppercase tracking-wider mb-1">DOM Title</span>
                                        <p className="text-slate-200 bg-slate-900/90 p-3 border border-slate-800 rounded-xl">{results.scraper.title || 'N/A'}</p>
                                    </div>
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                        <div>
                                            <span className="block text-slate-400 uppercase tracking-wider mb-1">Server Technology</span>
                                            <p className="text-purple-400 bg-slate-900/90 p-3 border border-slate-800 rounded-xl">{results.scraper.server || 'Undisclosed'}</p>
                                        </div>
                                        {results.whois?.status === 'success' && (
                                            <div>
                                                <span className="block text-slate-400 uppercase tracking-wider mb-1">Domain Expiration</span>
                                                <p className="text-emerald-400 bg-slate-900/90 p-3 border border-slate-800 rounded-xl">{results.whois.expiration || 'N/A'}</p>
                                            </div>
                                        )}
                                    </div>
                                    {results.scraper.description && (
                                        <div>
                                            <span className="block text-slate-400 uppercase tracking-wider mb-1">Meta Description</span>
                                            <p className="text-slate-300 bg-slate-900/90 p-3 border border-slate-800 rounded-xl italic font-sans text-xs">{results.scraper.description}</p>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* THREAT REPUTATION METRICS */}
                        {(targetType === 'ip' || targetType === 'domain') && (
                            <div className="p-6 border border-slate-800 rounded-2xl bg-slate-950/80 md:col-span-2">
                                <h3 className="text-base font-bold mb-4 text-white font-mono flex items-center gap-2">
                                    <ShieldAlert className="w-5 h-5 text-purple-400" />
                                    Global Threat Reputation Scoring
                                </h3>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {/* ThreatFox Malware Hits */}
                                    {results.threatfox && (
                                        <div className={`p-4 rounded-xl border ${results.threatfox.malware_hits > 0 ? 'bg-red-500/10 border-red-500/30' : 'bg-slate-900/90 border-slate-800'}`}>
                                            <span className="text-xs font-mono text-slate-400 block uppercase mb-1">Malware Indicators (ThreatFox)</span>
                                            <span className={`text-2xl font-bold font-mono ${results.threatfox.malware_hits > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                                                {results.threatfox.malware_hits} Hits
                                            </span>
                                        </div>
                                    )}

                                    {/* AbuseIPDB Score (IP Only) */}
                                    {targetType === 'ip' && results.abuseipdb && results.abuseipdb.status === 'success' && (
                                        <div className={`p-4 rounded-xl border ${results.abuseipdb.abuse_score > 20 ? 'bg-orange-500/10 border-orange-500/30' : 'bg-slate-900/90 border-slate-800'}`}>
                                            <span className="text-xs font-mono text-slate-400 block uppercase mb-1">Abuse Confidence Score (AbuseIPDB)</span>
                                            <span className={`text-2xl font-bold font-mono ${results.abuseipdb.abuse_score > 20 ? 'text-orange-400' : 'text-emerald-400'}`}>
                                                {results.abuseipdb.abuse_score} / 100
                                            </span>
                                            <p className="text-[11px] font-mono text-slate-500 mt-1">Calculated from {results.abuseipdb.total_reports} distinct telemetry reports</p>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* ADVANCED IP GEOLOCATION */}
                        {targetType === 'ip' && results.geolocation?.status === 'success' && (
                            <div className="p-6 border border-slate-800 rounded-2xl bg-slate-950/80 md:col-span-2">
                                <h3 className="text-base font-bold mb-4 text-white font-mono flex items-center gap-2">
                                    <MapPin className="w-5 h-5 text-purple-400" />
                                    Autonomous System & Geolocation Matrix
                                </h3>
                                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs">
                                    <div className="bg-slate-900/90 p-4 rounded-xl border border-slate-800">
                                        <span className="text-slate-400 block uppercase text-[11px]">Geographic Location</span>
                                        <span className="font-bold text-white mt-1 block truncate text-sm">{results.geolocation.city || 'Unknown'}, {results.geolocation.country}</span>
                                    </div>
                                    <div className="bg-slate-900/90 p-4 rounded-xl border border-slate-800">
                                        <span className="text-slate-400 block uppercase text-[11px]">Internet Service Provider</span>
                                        <span className="font-bold text-white mt-1 block truncate text-sm">{results.geolocation.isp || 'N/A'}</span>
                                    </div>
                                    <div className="bg-slate-900/90 p-4 rounded-xl border border-slate-800">
                                        <span className="text-slate-400 block uppercase text-[11px]">Autonomous System (ASN)</span>
                                        <span className="font-bold text-purple-400 mt-1 block truncate text-sm">{results.geolocation.asn || 'N/A'}</span>
                                    </div>
                                    <div className="bg-slate-900/90 p-4 rounded-xl border border-slate-800 flex flex-col justify-center gap-1.5">
                                        {results.geolocation.is_proxy ? (
                                            <span className="px-2.5 py-1 bg-red-500/20 text-red-300 border border-red-500/40 rounded text-[11px] font-bold text-center uppercase tracking-wider">
                                                🛡️ Proxy / VPN Detected
                                            </span>
                                        ) : (
                                            <span className="px-2.5 py-1 bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded text-[11px] font-bold text-center uppercase tracking-wider">
                                                ✅ Direct IP
                                            </span>
                                        )}
                                        {results.geolocation.is_hosting && (
                                            <span className="px-2.5 py-1 bg-yellow-500/20 text-yellow-300 border border-yellow-500/40 rounded text-[11px] font-bold text-center uppercase tracking-wider">
                                                🏢 Datacenter Range
                                            </span>
                                        )}
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* DOMAIN DNS RECORDS */}
                        {targetType === 'domain' && results.dns?.status === 'success' && results.dns.records?.length > 0 && (
                            <div className="p-6 border border-slate-800 rounded-2xl bg-slate-950/80">
                                <div className="flex items-center justify-between mb-3">
                                    <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                                        <Network className="w-4 h-4 text-purple-400" />
                                        DNS Resolution Records
                                    </h3>
                                    <span className="text-xs font-mono text-slate-500">{results.dns.records.length} records</span>
                                </div>
                                <div className="max-h-48 overflow-y-auto space-y-1.5 pr-2 scrollbar-thin scrollbar-thumb-slate-800">
                                    {results.dns.records.map((rec, idx) => (
                                        <div key={idx} className="p-2.5 bg-slate-900/90 border border-slate-800 rounded-lg text-xs text-slate-300 font-mono break-all flex justify-between items-center">
                                            <span>{rec}</span>
                                            <button onClick={() => copyToClipboard(rec, `dns-rec-${idx}`)} className="text-slate-500 hover:text-white ml-2">
                                                {copiedKey === `dns-rec-${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* DOMAIN SUBDOMAINS */}
                        {targetType === 'domain' && results.subdomains && (
                            <div className="p-6 border border-slate-800 rounded-2xl bg-slate-950/80">
                                <div className="flex items-center justify-between mb-3">
                                    <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                                        <Layers className="w-4 h-4 text-purple-400" />
                                        Subdomain Enumeration
                                    </h3>
                                    <span className="text-xs font-mono text-purple-400 bg-purple-950/60 border border-purple-500/30 px-2 py-0.5 rounded">
                                        {results.subdomains.count} Found
                                    </span>
                                </div>
                                <div className="max-h-48 overflow-y-auto space-y-1.5 pr-2 scrollbar-thin scrollbar-thumb-slate-800">
                                    {results.subdomains.subdomains?.map((sub, idx) => (
                                        <div key={idx} className="p-2.5 bg-slate-900/90 border border-slate-800 rounded-lg text-xs text-slate-300 font-mono truncate flex justify-between items-center">
                                            <span>{sub}</span>
                                            <button onClick={() => copyToClipboard(sub, `sub-${idx}`)} className="text-slate-500 hover:text-white ml-2">
                                                {copiedKey === `sub-${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* HISTORICAL WAYBACK URLS */}
                        {targetType === 'domain' && results.archived_urls && results.archived_urls.status === 'success' && (
                            <div className="p-6 border border-slate-800 rounded-2xl bg-slate-950/80 md:col-span-2">
                                <div className="flex items-center justify-between mb-3">
                                    <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                                        <History className="w-4 h-4 text-purple-400" />
                                        Historical Archive Endpoints (Wayback)
                                    </h3>
                                    <span className="text-xs font-mono text-slate-400">{results.archived_urls.count} URLs Indexed</span>
                                </div>
                                <div className="max-h-48 overflow-y-auto space-y-1.5 pr-2 scrollbar-thin scrollbar-thumb-slate-800">
                                    {results.archived_urls.urls?.map((url, idx) => (
                                        <div
                                            key={idx}
                                            onClick={() => window.open(url, '_blank')}
                                            className="p-2.5 bg-slate-900/90 border border-slate-800 rounded-lg text-xs text-slate-300 font-mono truncate hover:text-purple-400 hover:border-purple-500/40 cursor-pointer flex items-center justify-between group transition-colors"
                                        >
                                            <span className="truncate">{url}</span>
                                            <ExternalLink className="w-3.5 h-3.5 text-slate-500 group-hover:text-purple-400 shrink-0 ml-2" />
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                </motion.div>
            )}
        </div>
    );
}
