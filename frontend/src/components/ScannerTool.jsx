import { useState } from 'react';
import axios from 'axios';
import LoadingSpinner from './LoadingSpinner';
import { saveActivity } from '../utils/historyManager';

export default function ScannerTool() {
    const [url, setUrl] = useState('');
    const [loading, setLoading] = useState(false);

    const [results, setResults] = useState(null);
    const [advancedResults, setAdvancedResults] = useState(null);
    const [error, setError] = useState('');

    const scanUrl = async () => {
        setLoading(true);
        setError('');
        setResults(null);
        setAdvancedResults(null);

        try {
            const [basicResponse, advancedResponse] = await Promise.all([
                axios.post('http://127.0.0.1:8000/api/scanner/url', { url }),
                axios.post('http://127.0.0.1:8000/api/scanner/advanced', { url })
            ]);

            setResults(basicResponse.data);
            setAdvancedResults(advancedResponse.data);

            const vtMalicious = basicResponse.data.virustotal?.stats?.malicious || 0;
            const isPhishing = advancedResponse.data.phishing?.status === 'malicious';
            const riskLevel = (vtMalicious > 5 || isPhishing) ? 'CRITICAL' : (vtMalicious > 0) ? 'SUSPICIOUS' : 'SAFE';

            saveActivity({
                module: 'URL Scanner',
                action: 'URL Analysis',
                target: url,
                summary: `Threat Scan complete. Verdict: ${riskLevel} (${vtMalicious} malicious hits)`,
                fullResult: { basic: basicResponse.data, advanced: advancedResponse.data }
            });
        } catch (err) {
            setError(err.response?.data?.detail || 'An error occurred during scanning. The server might be unreachable.');
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
                color: "bg-slate-950 border-slate-700 text-slate-200",
                title: "☠️ Sinkholed or Offline Threat",
                description: "This domain was previously flagged as malicious, but it is currently offline and cannot resolve an IP address. The threat is likely neutralized."
            };
        }

        if (vtMalicious > 5 || isPhishing) {
            let threatType = isPhishing ? `Phishing (Imitating ${advancedResults.phishing.flagged_brand})` : "Malware/Malicious Host";
            return {
                level: "CRITICAL",
                color: "bg-red-950/70 border-red-700 text-red-100 shadow-[0_0_15px_rgba(220,38,38,0.3)]",
                title: `🚨 CRITICAL RISK: Active ${threatType}`,
                description: `This site is dangerous. Flagged by ${vtMalicious} security vendors${hasPulses ? ' and linked to known threat campaigns' : ''}. Do not interact with this domain.`
            };
        }

        if (vtMalicious > 0 || results.virustotal?.stats?.suspicious > 2) {
            return {
                level: "WARNING",
                color: "bg-yellow-950/70 border-yellow-700 text-yellow-100",
                title: "⚠️ SUSPICIOUS: Proceed with Caution",
                description: "This site has triggered warnings from security vendors. It may be compromised or hosting questionable content."
            };
        }

        return {
            level: "SAFE",
            color: "bg-emerald-950/70 border-emerald-700 text-emerald-100",
            title: "✅ No Obvious Threats Detected",
            description: "No security vendors have flagged this URL, and it does not match known typosquatting signatures."
        };
    };

    const verdict = generateVerdict();

    return (
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-2xl shadow-xl text-slate-100">
            <h2 className="text-2xl font-bold mb-2 text-white">Advanced Threat Intelligence Scanner</h2>
            <p className="text-slate-400 mb-6 text-sm">Analyze URLs against multi-source threat intelligence, SSL validity, and typosquatting engines.</p>

            <div className="flex gap-4 mb-6">
                <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="Enter URL (e.g., https://paypal-update-secure.com)"
                    className="flex-1 p-3 bg-slate-950 border border-slate-800 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-red-500 font-mono"
                />
                <button
                    onClick={scanUrl}
                    disabled={loading || !url}
                    className="px-8 py-3 bg-red-600 text-white font-bold rounded-lg hover:bg-red-700 disabled:opacity-50 transition-colors"
                >
                    {loading ? 'Analyzing...' : 'Scan Target'}
                </button>
            </div>

            {error && (
                <div className="p-4 bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg font-medium text-sm mb-4">
                    {error}
                </div>
            )}

            {loading && (
                <div className="my-12">
                    <LoadingSpinner text="Running advanced heuristics and visual capture..." color="#dc2626" />
                </div>
            )}

            {(results || advancedResults) && !loading && (
                <div className="mt-6 space-y-6">

                    {/* THREAT VERDICT BANNER */}
                    {verdict && (
                        <div className={`p-6 rounded-xl border ${verdict.color}`}>
                            <div className="flex items-center justify-between border-b border-white/10 pb-2 mb-3">
                                <h3 className="text-xl font-black tracking-wide">{verdict.title}</h3>
                                <span className="px-3 py-1 bg-white/10 rounded font-bold text-xs tracking-widest uppercase">
                                    {verdict.level}
                                </span>
                            </div>
                            <p className="font-medium text-sm opacity-90">{verdict.description}</p>
                        </div>
                    )}

                    {/* TOP ROW: Phishing Engine & SSL Inspector */}
                    {advancedResults && (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div className={`p-5 border rounded-xl ${advancedResults.phishing?.status === 'malicious' ? 'bg-red-500/10 border-red-500/30' : 'bg-emerald-500/10 border-emerald-500/30'}`}>
                                <h3 className={`text-lg font-bold mb-2 ${advancedResults.phishing?.status === 'malicious' ? 'text-red-400' : 'text-emerald-400'}`}>
                                    Typosquatting Engine
                                </h3>
                                <p className="text-slate-300 font-medium text-sm">{advancedResults.phishing?.message}</p>
                                {advancedResults.phishing?.status === 'malicious' && (
                                    <div className="mt-3 inline-block bg-red-500/20 text-red-300 border border-red-500/30 text-xs font-bold px-3 py-1 rounded">
                                        Levenshtein Match: {advancedResults.phishing.distance}
                                    </div>
                                )}
                            </div>

                            <div className="p-5 border border-slate-800 bg-slate-950 rounded-xl">
                                <h3 className="text-lg font-bold mb-3 text-white">SSL/TLS Inspection</h3>
                                {advancedResults.ssl?.status === 'success' ? (
                                    <div className="space-y-2">
                                        <div className="flex justify-between border-b border-slate-800 pb-1.5">
                                            <span className="text-xs text-slate-400 uppercase font-semibold">Issuer</span>
                                            <span className="font-semibold text-slate-200 text-sm">{advancedResults.ssl.issuer}</span>
                                        </div>
                                        <div className="flex justify-between border-b border-slate-800 pb-1.5">
                                            <span className="text-xs text-slate-400 uppercase font-semibold">Expires On</span>
                                            <span className="font-mono text-slate-300 text-sm">{advancedResults.ssl.expires}</span>
                                        </div>
                                        <div className="flex justify-between pt-1">
                                            <span className="text-xs text-slate-400 uppercase font-semibold">Validity</span>
                                            <span className={`font-bold text-sm ${advancedResults.ssl.days_remaining < 30 ? 'text-red-400' : 'text-emerald-400'}`}>
                                                {advancedResults.ssl.days_remaining} Days Remaining
                                            </span>
                                        </div>
                                    </div>
                                ) : (
                                    <p className="text-red-400 font-medium text-sm">{advancedResults.ssl?.error || "Could not retrieve SSL certificate."}</p>
                                )}
                            </div>
                        </div>
                    )}

                    {/* MIDDLE ROW: Visual Capture */}
                    {advancedResults?.visual_capture && (
                        <div className="p-5 border border-slate-800 bg-slate-950 rounded-xl">
                            <h3 className="text-lg font-bold mb-4 text-white">Safe Visual Capture</h3>
                            {advancedResults.visual_capture.status === 'success' ? (
                                <div className="border border-slate-800 rounded-lg overflow-hidden shadow-lg">
                                    <img
                                        src={advancedResults.visual_capture.image_data}
                                        alt="Target Screenshot"
                                        className="w-full object-cover"
                                    />
                                </div>
                            ) : (
                                <p className="text-red-400 bg-red-500/10 p-3 rounded-lg border border-red-500/20 text-sm">
                                    Capture Failed: {advancedResults.visual_capture.error}
                                </p>
                            )}
                        </div>
                    )}

                    {/* BOTTOM ROW: Threat Intel (VirusTotal & OTX) */}
                    {results && (
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            <div className="p-5 border border-slate-800 bg-slate-950 rounded-xl">
                                <h3 className="text-lg font-bold mb-4 text-white">VirusTotal Aggregate</h3>
                                {results.virustotal?.status === 'queued' ? (
                                    <p className="text-blue-400 text-sm">{results.virustotal.message}</p>
                                ) : results.virustotal?.stats ? (
                                    <div className="grid grid-cols-2 gap-3 text-center">
                                        <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                                            <span className="block text-2xl font-bold text-red-400">{results.virustotal.stats.malicious}</span>
                                            <span className="text-xs font-semibold uppercase text-red-400/70">Malicious</span>
                                        </div>
                                        <div className="p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                                            <span className="block text-2xl font-bold text-yellow-400">{results.virustotal.stats.suspicious}</span>
                                            <span className="text-xs font-semibold uppercase text-yellow-400/70">Suspicious</span>
                                        </div>
                                        <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
                                            <span className="block text-2xl font-bold text-emerald-400">{results.virustotal.stats.harmless}</span>
                                            <span className="text-xs font-semibold uppercase text-emerald-400/70">Harmless</span>
                                        </div>
                                        <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg">
                                            <span className="block text-2xl font-bold text-slate-300">{results.virustotal.stats.undetected}</span>
                                            <span className="text-xs font-semibold uppercase text-slate-500">Undetected</span>
                                        </div>
                                    </div>
                                ) : (
                                    <p className="text-red-400 text-sm">Could not fetch VirusTotal data.</p>
                                )}
                            </div>

                            <div className="p-5 border border-slate-800 bg-slate-950 rounded-xl">
                                <h3 className="text-lg font-bold text-white mb-4">AlienVault OTX Pulses</h3>
                                {results.alienvault?.status === 'completed' ? (
                                    <div>
                                        <p className="mb-3 text-slate-300 font-medium text-sm">
                                            Associated Threat Campaigns:
                                            <span className={`ml-2 px-2.5 py-0.5 rounded text-xs font-bold ${results.alienvault.pulse_count > 0 ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' : 'bg-slate-900 text-slate-400'}`}>
                                                {results.alienvault.pulse_count}
                                            </span>
                                        </p>

                                        {results.alienvault.pulse_count > 0 && (
                                            <ul className="mt-2 space-y-2 max-h-40 overflow-y-auto pr-2">
                                                {results.alienvault.recent_pulses.map((pulse, idx) => (
                                                    <li key={idx} className="text-xs bg-slate-900 p-2.5 border border-slate-800 rounded text-slate-300 flex items-start gap-2">
                                                        <span className="text-red-400">🚨</span> {pulse}
                                                    </li>
                                                ))}
                                            </ul>
                                        )}
                                    </div>
                                ) : (
                                    <p className="text-red-400 text-sm">Could not fetch AlienVault data.</p>
                                )}
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
