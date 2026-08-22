import { useState } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import {
    ShieldAlert,
    ShieldCheck,
    AlertTriangle,
    Radio,
    Lock,
    Eye,
    FileWarning,
    ExternalLink,
    Copy,
    Check,
    Zap,
    AlertCircle,
    Search,
    Globe,
    Terminal
} from 'lucide-react';
import LoadingSpinner from './LoadingSpinner';
import { saveActivity } from '../utils/historyManager';

const PRESET_URLS = [
    { label: 'PayPal Phish Sample', url: 'https://paypal-update-account-verification.com' },
    { label: 'Legitimate Domain', url: 'https://github.com' }
];

export default function ScannerTool() {
    const [url, setUrl] = useState('');
    const [loading, setLoading] = useState(false);
    const [copiedKey, setCopiedKey] = useState(null);

    const [results, setResults] = useState(null);
    const [advancedResults, setAdvancedResults] = useState(null);
    const [error, setError] = useState('');

    const API_BASE = import.meta.env.VITE_API_BASE_URL
        ? `${import.meta.env.VITE_API_BASE_URL}/api/scanner`
        : 'http://127.0.0.1:8000/api/scanner';

    const copyToClipboard = (text, key) => {
        if (!text) return;
        navigator.clipboard.writeText(text);
        setCopiedKey(key);
        setTimeout(() => setCopiedKey(null), 2000);
    };

    const scanUrl = async () => {
        if (!url.trim()) return;
        setLoading(true);
        setError('');
        setResults(null);
        setAdvancedResults(null);

        try {
            const [basicResponse, advancedResponse] = await Promise.all([
                axios.post(`${API_BASE}/url`, { url: url.trim() }),
                axios.post(`${API_BASE}/advanced`, { url: url.trim() })
            ]);

            setResults(basicResponse.data);
            setAdvancedResults(advancedResponse.data);

            const vtMalicious = basicResponse.data.virustotal?.stats?.malicious || 0;
            const isPhishing = advancedResponse.data.phishing?.status === 'malicious';
            const riskLevel = (vtMalicious > 5 || isPhishing) ? 'CRITICAL' : (vtMalicious > 0) ? 'SUSPICIOUS' : 'SAFE';

            saveActivity({
                module: 'URL Scanner',
                action: 'Threat Analysis',
                target: url.trim(),
                summary: `Threat Scan complete. Verdict: ${riskLevel} (${vtMalicious} malicious hits)`,
                fullResult: { basic: basicResponse.data, advanced: advancedResponse.data }
            });
        } catch (err) {
            setError(err.response?.data?.detail || 'An error occurred during scanning. The threat intelligence backend might be unreachable.');
        } finally {
            setLoading(false);
        }
    };

    // --- THREAT VERDICT ENGINE ---
    const generateVerdict = () => {
        if (!results || !advancedResults) return null;

        const vtMalicious = results.virustotal?.stats?.malicious || 0;
        const isPhishing = advancedResults.phishing?.status === 'malicious';
        const isOffline = advancedResults.ssl?.error?.includes('offline') || advancedResults.ssl?.error?.includes('Failed');
        const hasPulses = results.alienvault?.pulse_count > 0;

        if (isOffline && (vtMalicious > 0 || hasPulses)) {
            return {
                level: "NEUTRALIZED",
                badgeColor: "bg-slate-800 text-slate-300 border-slate-700",
                containerColor: "bg-slate-950/90 border-slate-700/80 text-slate-200",
                title: "Sinkholed or Offline Threat",
                icon: AlertCircle,
                iconColor: "text-slate-400",
                description: "This domain was previously flagged as malicious, but it is currently offline and unable to resolve. The vector is neutralized."
            };
        }

        if (vtMalicious > 5 || isPhishing) {
            let threatType = isPhishing ? `Phishing Attack (Imitating ${advancedResults.phishing.flagged_brand || 'Brand'})` : "Active Malware / Malicious Host";
            return {
                level: "CRITICAL",
                badgeColor: "bg-red-500/20 text-red-300 border-red-500/40",
                containerColor: "bg-red-950/40 border-red-500/50 text-red-100 shadow-[0_0_30px_rgba(239,68,68,0.25)]",
                title: `CRITICAL THREAT: ${threatType}`,
                icon: ShieldAlert,
                iconColor: "text-red-400",
                description: `Dangerous entity flagged by ${vtMalicious} security vendors${hasPulses ? ' and linked to active adversarial campaigns' : ''}. Block all network access immediately.`
            };
        }

        if (vtMalicious > 0 || results.virustotal?.stats?.suspicious > 2) {
            return {
                level: "WARNING",
                badgeColor: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
                containerColor: "bg-yellow-950/40 border-yellow-500/50 text-yellow-100 shadow-[0_0_25px_rgba(234,179,8,0.2)]",
                title: "SUSPICIOUS: Proceed with High Caution",
                icon: AlertTriangle,
                iconColor: "text-yellow-400",
                description: "This site triggered anomalous behavioral heuristics and security flags. It may be hosting unverified payloads or staging infrastructure."
            };
        }

        return {
            level: "SAFE",
            badgeColor: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
            containerColor: "bg-emerald-950/40 border-emerald-500/50 text-emerald-100 shadow-[0_0_25px_rgba(16,185,129,0.2)]",
            title: "NO KNOWN THREATS DETECTED",
            icon: ShieldCheck,
            iconColor: "text-emerald-400",
            description: "No security engines have flagged this target, and typosquatting distance signatures indicate standard brand legitimacy."
        };
    };

    const verdict = generateVerdict();

    return (
        <div className="w-full bg-slate-900/60 backdrop-blur-xl border border-slate-800/80 rounded-2xl shadow-[0_0_50px_rgba(0,0,0,0.5)] p-6 sm:p-8 text-slate-200 relative overflow-hidden">
            {/* Ambient Background Glow */}
            <div className="absolute top-0 right-0 w-96 h-96 bg-red-600/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>

            {/* Top Tactical Header */}
            <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 mb-8 border-b border-slate-800/80">
                <div className="flex items-center gap-4">
                    <div className="p-3 bg-red-500/10 rounded-xl border border-red-500/30 shadow-[0_0_20px_rgba(239,68,68,0.2)]">
                        <ShieldAlert className="w-7 h-7 text-red-400" />
                    </div>
                    <div>
                        <div className="flex items-center gap-2 mb-1">
                            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-wide">Threat Scanner</h2>
                        </div>
                        <p className="text-sm text-slate-400 font-mono">
                            Multi-vendor reputation analysis, typosquatting heuristics, and automated sandboxing.
                        </p>
                    </div>
                </div>

                <div className="flex items-center gap-2 self-start md:self-auto bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800 text-xs font-mono text-slate-400">
                    <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse"></span>
                    <span>INTEL-FEEDS: ONLINE</span>
                </div>
            </div>

            {/* Ingestion & Target Input Area */}
            <div className="relative z-10 bg-slate-950/60 border border-slate-800/80 rounded-2xl p-5 sm:p-6 mb-8 shadow-inner">
                <div className="flex flex-col sm:flex-row items-center justify-between gap-2 mb-4">
                    <span className="text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Globe className="w-3.5 h-3.5 text-red-400" />
                        Target URL or FQDN
                    </span>
                    <div className="flex items-center gap-2 self-start sm:self-auto">
                        <span className="text-[11px] font-mono text-slate-500 uppercase">Presets:</span>
                        {PRESET_URLS.map((preset, idx) => (
                            <button
                                key={idx}
                                onClick={() => setUrl(preset.url)}
                                className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white rounded-lg text-xs font-mono border border-slate-800 transition-colors"
                            >
                                {preset.label}
                            </button>
                        ))}
                    </div>
                </div>

                <div className="flex flex-col sm:flex-row gap-3">
                    <div className="relative flex-1">
                        <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                            <Search className="w-4 h-4 text-slate-500" />
                        </div>
                        <input
                            type="text"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            placeholder="Enter target URL (e.g., https://paypal-security-alert.com)"
                            className="w-full pl-10 pr-4 py-3 bg-slate-900/80 border border-slate-700/80 rounded-xl text-white font-mono text-sm placeholder-slate-500 focus:border-red-500 focus:ring-1 focus:ring-red-500 focus:outline-none transition-all"
                            onKeyDown={(e) => e.key === 'Enter' && scanUrl()}
                        />
                    </div>
                    <button
                        onClick={scanUrl}
                        disabled={loading || !url.trim()}
                        className="px-8 py-3 bg-red-600 hover:bg-red-500 text-white font-bold rounded-xl shadow-[0_0_25px_rgba(239,68,68,0.3)] disabled:opacity-50 disabled:shadow-none transition-all flex items-center justify-center gap-2 shrink-0 font-mono text-sm"
                    >
                        <Zap className="w-4 h-4" />
                        {loading ? 'Analyzing Threat...' : 'Launch Radar'}
                    </button>
                </div>
            </div>

            {/* Error Message */}
            {error && (
                <div className="relative z-10 p-4 bg-red-950/40 border border-red-500/40 text-red-300 rounded-xl font-medium text-sm mb-6 flex items-start gap-3 shadow-lg font-mono">
                    <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                    <div>
                        <span className="font-bold text-red-200 block">SCANNER_ERROR:</span>
                        <span>{error}</span>
                    </div>
                </div>
            )}

            {/* Loading Indicator */}
            {loading && (
                <div className="relative z-10 my-10">
                    <LoadingSpinner text="Querying global threat feeds, evaluating Levenshtein models & capturing DOM..." color="#ef4444" />
                </div>
            )}

            {/* Results Display */}
            {(results || advancedResults) && !loading && (
                <motion.div
                    initial={{ opacity: 0, y: 15 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.25 }}
                    className="relative z-10 space-y-6"
                >
                    {/* THREAT VERDICT BANNER */}
                    {verdict && (
                        <div className={`p-6 rounded-2xl border ${verdict.containerColor}`}>
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4 mb-4">
                                <div className="flex items-center gap-3">
                                    <verdict.icon className={`w-6 h-6 ${verdict.iconColor}`} />
                                    <h3 className="text-xl font-black tracking-wide text-white font-mono">{verdict.title}</h3>
                                </div>
                                <span className={`px-3 py-1 rounded-lg font-mono font-bold text-xs tracking-widest uppercase border self-start sm:self-auto ${verdict.badgeColor}`}>
                                    {verdict.level}
                                </span>
                            </div>
                            <p className="font-sans text-sm text-slate-200 leading-relaxed">{verdict.description}</p>
                        </div>
                    )}

                    {/* TOP ROW: Phishing Engine & SSL Inspector */}
                    {advancedResults && (
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            {/* Typosquatting / Levenshtein */}
                            <div className={`p-6 rounded-2xl border ${advancedResults.phishing?.status === 'malicious'
                                ? 'bg-red-950/30 border-red-500/40'
                                : 'bg-slate-950/80 border-slate-800'
                                }`}>
                                <div className="flex items-center justify-between mb-4">
                                    <div className="flex items-center gap-2">
                                        <FileWarning className={`w-5 h-5 ${advancedResults.phishing?.status === 'malicious' ? 'text-red-400' : 'text-emerald-400'}`} />
                                        <h3 className="text-base font-bold text-white tracking-wide font-mono">Typosquatting Engine</h3>
                                    </div>
                                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${advancedResults.phishing?.status === 'malicious'
                                        ? 'bg-red-500/10 text-red-400 border-red-500/30'
                                        : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                                        }`}>
                                        {advancedResults.phishing?.status === 'malicious' ? 'TRIGGERED' : 'CLEAR'}
                                    </span>
                                </div>
                                <p className="text-slate-300 text-sm mb-4 leading-relaxed">{advancedResults.phishing?.message}</p>
                                {advancedResults.phishing?.status === 'malicious' && (
                                    <div className="flex flex-wrap gap-2 pt-2 border-t border-red-500/20">
                                        <span className="bg-red-500/20 text-red-300 border border-red-500/40 text-xs font-mono font-bold px-3 py-1 rounded-lg">
                                            Levenshtein Distance: {advancedResults.phishing.distance}
                                        </span>
                                        {advancedResults.phishing.flagged_brand && (
                                            <span className="bg-red-500/20 text-red-300 border border-red-500/40 text-xs font-mono font-bold px-3 py-1 rounded-lg">
                                                Target Imitation: {advancedResults.phishing.flagged_brand}
                                            </span>
                                        )}
                                    </div>
                                )}
                            </div>

                            {/* SSL/TLS Inspection */}
                            <div className="p-6 rounded-2xl border border-slate-800 bg-slate-950/80">
                                <div className="flex items-center justify-between mb-4">
                                    <div className="flex items-center gap-2">
                                        <Lock className="w-5 h-5 text-blue-400" />
                                        <h3 className="text-base font-bold text-white tracking-wide font-mono">SSL / TLS Inspection</h3>
                                    </div>
                                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${advancedResults.ssl?.status === 'success'
                                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                                        : 'bg-red-500/10 text-red-400 border-red-500/30'
                                        }`}>
                                        {advancedResults.ssl?.status === 'success' ? 'VALID_CERT' : 'INVALID_CERT'}
                                    </span>
                                </div>

                                {advancedResults.ssl?.status === 'success' ? (
                                    <div className="space-y-3 font-mono text-xs">
                                        <div className="flex justify-between items-center bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                                            <span className="text-slate-400 uppercase">Issuer Authority</span>
                                            <span className="text-white font-semibold">{advancedResults.ssl.issuer}</span>
                                        </div>
                                        <div className="flex justify-between items-center bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                                            <span className="text-slate-400 uppercase">Expiration Date</span>
                                            <span className="text-slate-300">{advancedResults.ssl.expires}</span>
                                        </div>
                                        <div className="flex justify-between items-center bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                                            <span className="text-slate-400 uppercase">Days Remaining</span>
                                            <span className={`font-bold ${advancedResults.ssl.days_remaining < 30 ? 'text-red-400' : 'text-emerald-400'}`}>
                                                {advancedResults.ssl.days_remaining} Days
                                            </span>
                                        </div>
                                    </div>
                                ) : (
                                    <p className="text-red-400 font-mono text-xs bg-red-950/30 p-3 rounded-lg border border-red-500/30">
                                        {advancedResults.ssl?.error || "Could not retrieve SSL certificate."}
                                    </p>
                                )}
                            </div>
                        </div>
                    )}

                    {/* MIDDLE ROW: Visual Sandbox Capture */}
                    {advancedResults?.visual_capture && (
                        <div className="p-6 border border-slate-800 bg-slate-950/80 rounded-2xl shadow-xl">
                            <div className="flex items-center justify-between mb-4">
                                <div className="flex items-center gap-2">
                                    <Eye className="w-5 h-5 text-red-400" />
                                    <h3 className="text-base font-bold text-white tracking-wide font-mono">Headless DOM Sandbox Snapshot</h3>
                                </div>
                                <span className="text-xs font-mono text-slate-500">ISOLATED_CONTAINER</span>
                            </div>

                            {advancedResults.visual_capture.status === 'success' ? (
                                <div className="border border-slate-800 rounded-xl overflow-hidden shadow-2xl bg-slate-900">
                                    {/* Mockup Browser Top Bar */}
                                    <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
                                        <div className="flex items-center gap-1.5">
                                            <div className="w-2.5 h-2.5 rounded-full bg-red-500/80"></div>
                                            <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/80"></div>
                                            <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80"></div>
                                        </div>
                                        <div className="font-mono text-[11px] text-slate-400 bg-slate-950 px-3 py-1 rounded-md border border-slate-800 truncate max-w-md">
                                            {url}
                                        </div>
                                        <div className="w-8"></div>
                                    </div>
                                    <img
                                        src={advancedResults.visual_capture.image_data}
                                        alt="Target DOM Capture"
                                        className="w-full object-cover max-h-[480px]"
                                    />
                                </div>
                            ) : (
                                <p className="text-red-400 bg-red-950/30 p-4 rounded-xl border border-red-500/30 text-xs font-mono">
                                    Capture Failed: {advancedResults.visual_capture.error}
                                </p>
                            )}
                        </div>
                    )}

                    {/* BOTTOM ROW: Threat Intel (VirusTotal & OTX) */}
                    {results && (
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            {/* VirusTotal Metrics Card */}
                            <div className="p-6 border border-slate-800 bg-slate-950/80 rounded-2xl">
                                <div className="flex items-center justify-between mb-4">
                                    <h3 className="text-base font-bold text-white tracking-wide font-mono">VirusTotal Feed Intelligence</h3>
                                    <span className="text-xs font-mono text-slate-500">AGGREGATE_STATS</span>
                                </div>

                                {results.virustotal?.status === 'queued' ? (
                                    <p className="text-blue-400 text-sm font-mono">{results.virustotal.message}</p>
                                ) : results.virustotal?.stats ? (
                                    <div className="grid grid-cols-2 gap-3">
                                        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-center">
                                            <span className="block text-2xl font-bold font-mono text-red-400">{results.virustotal.stats.malicious}</span>
                                            <span className="text-[11px] font-mono uppercase tracking-wider text-red-400/80">Malicious Hits</span>
                                        </div>
                                        <div className="p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-xl text-center">
                                            <span className="block text-2xl font-bold font-mono text-yellow-400">{results.virustotal.stats.suspicious}</span>
                                            <span className="text-[11px] font-mono uppercase tracking-wider text-yellow-400/80">Suspicious</span>
                                        </div>
                                        <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-center">
                                            <span className="block text-2xl font-bold font-mono text-emerald-400">{results.virustotal.stats.harmless}</span>
                                            <span className="text-[11px] font-mono uppercase tracking-wider text-emerald-400/80">Harmless</span>
                                        </div>
                                        <div className="p-4 bg-slate-900/90 border border-slate-800 rounded-xl text-center">
                                            <span className="block text-2xl font-bold font-mono text-slate-300">{results.virustotal.stats.undetected}</span>
                                            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-500">Undetected</span>
                                        </div>
                                    </div>
                                ) : (
                                    <p className="text-red-400 text-xs font-mono">Could not fetch VirusTotal data.</p>
                                )}
                            </div>

                            {/* AlienVault OTX Threat Pulses */}
                            <div className="p-6 border border-slate-800 bg-slate-950/80 rounded-2xl">
                                <div className="flex items-center justify-between mb-4">
                                    <h3 className="text-base font-bold text-white tracking-wide font-mono">AlienVault OTX Threat Feed</h3>
                                    <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold ${results.alienvault?.pulse_count > 0
                                        ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                                        : 'bg-slate-900 text-slate-400 border border-slate-800'
                                        }`}>
                                        {results.alienvault?.pulse_count || 0} Pulses
                                    </span>
                                </div>

                                {results.alienvault?.status === 'completed' ? (
                                    <div>
                                        <p className="text-xs font-mono text-slate-400 mb-3">
                                            Active threat adversary correlations identified in global telemetry:
                                        </p>

                                        {results.alienvault.pulse_count > 0 ? (
                                            <ul className="space-y-2 max-h-48 overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-slate-800">
                                                {results.alienvault.recent_pulses.map((pulse, idx) => (
                                                    <li key={idx} className="text-xs bg-slate-900/90 p-3 border border-slate-800 rounded-xl text-slate-200 flex items-start justify-between gap-2">
                                                        <div className="flex items-start gap-2">
                                                            <span className="text-red-400 font-mono">🚨</span>
                                                            <span className="font-mono">{pulse}</span>
                                                        </div>
                                                        <button
                                                            onClick={() => copyToClipboard(pulse, `pulse-${idx}`)}
                                                            className="text-slate-500 hover:text-white shrink-0"
                                                            title="Copy"
                                                        >
                                                            {copiedKey === `pulse-${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                                                        </button>
                                                    </li>
                                                ))}
                                            </ul>
                                        ) : (
                                            <div className="text-center py-8 text-slate-500 font-mono text-xs bg-slate-900/50 rounded-xl border border-slate-800/60">
                                                No linked malicious OTX pulse campaigns detected.
                                            </div>
                                        )}
                                    </div>
                                ) : (
                                    <p className="text-red-400 text-xs font-mono">Could not fetch AlienVault intelligence data.</p>
                                )}
                            </div>
                        </div>
                    )}
                </motion.div>
            )}
        </div>
    );
}
