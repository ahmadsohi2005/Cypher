import { useState, useEffect } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Activity,
    Wifi,
    Radio,
    Server,
    Route,
    Globe,
    FileSearch,
    Cpu,
    Calculator,
    ShieldCheck,
    Copy,
    Check,
    ArrowRight,
    AlertCircle,
    Terminal,
    Zap
} from 'lucide-react';
import LoadingSpinner from './LoadingSpinner';
import { saveActivity } from '../utils/historyManager';

const SUB_TABS = [
    { id: 'ping', label: 'Ping', icon: Wifi, desc: 'ICMP Latency & Host Reachability' },
    { id: 'sweep', label: 'Ping Sweep', icon: Radio, desc: 'Subnet Host Discovery Matrix' },
    { id: 'ports', label: 'Port Scanner', icon: Server, desc: 'TCP Port Audit & Banner Grab' },
    { id: 'traceroute', label: 'Traceroute', icon: Route, desc: 'Network Path & Hop Telemetry' },
    { id: 'dns', label: 'DNS Lookup', icon: Globe, desc: 'Zone Record Query (A, MX, NS...)' },
    { id: 'whois', label: 'WHOIS Lookup', icon: FileSearch, desc: 'Registrar & Ownership Intel' },
    { id: 'mac', label: 'MAC Profiler', icon: Cpu, desc: 'Hardware Vendor & OUI Resolution' },
    { id: 'subnet', label: 'Subnet Calc', icon: Calculator, desc: 'CIDR Range & Host Topology' },
    { id: 'ssl', label: 'SSL Inspector', icon: ShieldCheck, desc: 'TLS Certificate & Validity Audit' }
];

export default function NetworkTool() {
    const [subTab, setSubTab] = useState('ping');
    const [target, setTarget] = useState('');
    const [copiedKey, setCopiedKey] = useState(null);

    // UI State
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState('');

    // Tool Specific State
    const [baseIp, setBaseIp] = useState('192.168.1.');
    const [startIp, setStartIp] = useState(1);
    const [endIp, setEndIp] = useState(20);
    const [portProfile, setPortProfile] = useState('top10');
    const [macAddress, setMacAddress] = useState('');
    const [cidrInput, setCidrInput] = useState('192.168.1.0/24');

    // Dynamic API routing for Vercel vs Localhost
    const API_BASE = import.meta.env.VITE_API_BASE_URL
        ? `${import.meta.env.VITE_API_BASE_URL}/api/network`
        : 'http://127.0.0.1:8000/api/network';

    // Reset states when switching tabs to prevent UI freeze
    useEffect(() => {
        setLoading(false);
        setResults(null);
        setError('');
    }, [subTab]);

    const copyToClipboard = (text, key) => {
        if (!text) return;
        navigator.clipboard.writeText(typeof text === 'object' ? JSON.stringify(text, null, 2) : text);
        setCopiedKey(key);
        setTimeout(() => setCopiedKey(null), 2000);
    };

    const executeAction = async (endpoint, payload) => {
        setLoading(true);
        setError('');
        setResults(null);
        try {
            const response = await axios.post(`${API_BASE}/${endpoint}`, payload, {
                timeout: 25000
            });
            setResults(response.data);
            saveActivity({
                module: 'Network',
                action: subTab.toUpperCase(),
                target: target || baseIp || macAddress || cidrInput,
                summary: 'Diagnostics completed successfully',
                fullResult: response.data
            });
        } catch (err) {
            if (err.code === 'ECONNABORTED') {
                setError('The scan timed out. The target network is too slow or dropping packets.');
            } else {
                setError(err.response?.data?.detail || err.response?.data?.error || 'Operation failed or server unreachable');
            }
        } finally {
            setLoading(false);
        }
    };

    const handlePortScan = () => {
        const ports = portProfile === 'top10'
            ? [21, 22, 23, 25, 53, 80, 110, 443, 3389, 8080]
            : portProfile === 'web'
                ? [80, 443, 8000, 8080, 8443]
                : Array.from({ length: 1024 }, (_, i) => i + 1);

        executeAction('scan-ports', { target, ports });
    };

    const currentTabInfo = SUB_TABS.find(t => t.id === subTab) || SUB_TABS[0];

    return (
        <div className="w-full bg-slate-900/60 backdrop-blur-xl border border-slate-800/80 rounded-2xl shadow-[0_0_50px_rgba(0,0,0,0.5)] p-6 sm:p-8 text-slate-200 relative overflow-hidden">
            {/* Ambient Background Glow */}
            <div className="absolute top-0 right-0 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>

            {/* Top Tactical Header */}
            <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 mb-8 border-b border-slate-800/80">
                <div className="flex items-center gap-4">
                    <div className="p-3 bg-blue-500/10 rounded-xl border border-blue-500/30 shadow-[0_0_20px_rgba(59,130,246,0.2)]">
                        <Activity className="w-7 h-7 text-blue-400" />
                    </div>
                    <div>
                        <div className="flex items-center gap-2 mb-1">
                            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-wide">Network Diagnostics</h2>
                        </div>
                        <p className="text-sm text-slate-400 font-mono">
                            Passive discovery, active routing probes, and infrastructure telemetry.
                        </p>
                    </div>
                </div>

                <div className="flex items-center gap-2 self-start md:self-auto bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800 text-xs font-mono text-slate-400">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span>ENGINE_STATUS: READY</span>
                </div>
            </div>

            {/* Tactical Sub-Navigation Bar */}
            <div className="relative z-10 mb-8">
                <div className="flex gap-2 overflow-x-auto pb-2 scrollbar-thin scrollbar-thumb-slate-800 scrollbar-track-transparent">
                    {SUB_TABS.map((tab) => {
                        const Icon = tab.icon;
                        const isActive = subTab === tab.id;
                        return (
                            <button
                                key={tab.id}
                                onClick={() => setSubTab(tab.id)}
                                className={`flex items-center gap-2.5 px-4 py-2.5 rounded-xl font-medium text-xs sm:text-sm whitespace-nowrap transition-all duration-200 border ${isActive
                                        ? 'bg-blue-600/20 text-blue-300 border-blue-500/60 shadow-[0_0_20px_rgba(59,130,246,0.25)] font-semibold'
                                        : 'bg-slate-950/40 text-slate-400 border-slate-800/80 hover:bg-slate-800/60 hover:text-slate-200 hover:border-slate-700'
                                    }`}
                            >
                                <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-slate-500'}`} />
                                <span>{tab.label}</span>
                            </button>
                        );
                    })}
                </div>
                <div className="flex items-center gap-2 mt-2 px-1 text-xs text-slate-500 font-mono">
                    <Terminal className="w-3.5 h-3.5 text-blue-400" />
                    <span>Mode: <span className="text-slate-300">{currentTabInfo.desc}</span></span>
                </div>
            </div>

            {/* Inputs Card Area */}
            <div className="relative z-10 bg-slate-950/60 border border-slate-800/80 rounded-2xl p-5 sm:p-6 mb-8 shadow-inner">
                {/* 1. PING */}
                {subTab === 'ping' && (
                    <div className="flex flex-col sm:flex-row gap-3">
                        <div className="relative flex-1">
                            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                                <Wifi className="w-4 h-4 text-slate-500" />
                            </div>
                            <input
                                type="text"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                placeholder="Target host or IP (e.g., google.com, 1.1.1.1)"
                                className="w-full pl-10 pr-4 py-3 bg-slate-900/80 border border-slate-700/80 rounded-xl text-white font-mono text-sm placeholder-slate-500 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none transition-all"
                            />
                        </div>
                        <button
                            onClick={() => executeAction('ping', { target })}
                            disabled={loading || !target}
                            className="px-7 py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl shadow-[0_0_20px_rgba(37,99,235,0.3)] disabled:opacity-50 disabled:shadow-none transition-all flex items-center justify-center gap-2 shrink-0 font-mono text-sm"
                        >
                            <Zap className="w-4 h-4" />
                            {loading ? 'Pinging...' : 'Send Probe'}
                        </button>
                    </div>
                )}

                {/* 2. SWEEP */}
                {subTab === 'sweep' && (
                    <div className="flex flex-col gap-4">
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                            <div className="relative">
                                <label className="block text-[11px] uppercase tracking-wider text-slate-400 font-mono mb-1.5">Base Subnet IP</label>
                                <input
                                    type="text"
                                    value={baseIp}
                                    onChange={(e) => setBaseIp(e.target.value)}
                                    placeholder="e.g., 192.168.1."
                                    className="w-full px-3.5 py-2.5 bg-slate-900/80 border border-slate-700/80 rounded-xl text-white font-mono text-sm placeholder-slate-500 focus:border-blue-500 focus:outline-none"
                                />
                            </div>
                            <div>
                                <label className="block text-[11px] uppercase tracking-wider text-slate-400 font-mono mb-1.5">Start Host</label>
                                <input
                                    type="number"
                                    value={startIp}
                                    onChange={(e) => setStartIp(Number(e.target.value))}
                                    placeholder="1"
                                    className="w-full px-3.5 py-2.5 bg-slate-900/80 border border-slate-700/80 rounded-xl text-white font-mono text-sm placeholder-slate-500 focus:border-blue-500 focus:outline-none"
                                />
                            </div>
                            <div>
                                <label className="block text-[11px] uppercase tracking-wider text-slate-400 font-mono mb-1.5">End Host</label>
                                <input
                                    type="number"
                                    value={endIp}
                                    onChange={(e) => setEndIp(Number(e.target.value))}
                                    placeholder="20"
                                    className="w-full px-3.5 py-2.5 bg-slate-900/80 border border-slate-700/80 rounded-xl text-white font-mono text-sm placeholder-slate-500 focus:border-blue-500 focus:outline-none"
                                />
                            </div>
                        </div>
                        <button
                            onClick={() => executeAction('ping-sweep', { base_ip: baseIp, start: startIp, end: endIp })}
                            disabled={loading || !baseIp}
                            className="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl shadow-[0_0_20px_rgba(37,99,235,0.3)] disabled:opacity-50 disabled:shadow-none transition-all flex items-center justify-center gap-2 font-mono text-sm"
                        >
                            <Radio className="w-4 h-4" />
                            {loading ? 'Sweeping Subnet Range...' : 'Launch Ping Sweep'}
                        </button>
                    </div>
                )}

                {/* 3. PORTS */}
                {subTab === 'ports' && (
                    <div className="flex flex-col gap-4">
                        <div className="relative">
                            <label className="block text-[11px] uppercase tracking-wider text-slate-400 font-mono mb-1.5">Target IP / Domain</label>
                            <input
                                type="text"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                placeholder="Target IP or Domain (e.g., 192.168.1.1, scanme.nmap.org)"
                                className="w-full px-4 py-3 bg-slate-900/80 border border-slate-700/80 rounded-xl text-white font-mono text-sm placeholder-slate-500 focus:border-blue-500 focus:outline-none"
                            />
                        </div>
                        <div className="flex flex-col sm:flex-row items-center gap-3">
                            <div className="relative flex-1 w-full">
                                <select
                                    value={portProfile}
                                    onChange={(e) => setPortProfile(e.target.value)}
                                    className="w-full px-4 py-3 bg-slate-900/80 border border-slate-700/80 rounded-xl text-white font-mono text-sm focus:border-blue-500 focus:outline-none cursor-pointer"
                                >
                                    <option value="top10">Top 10 Essential Ports (21, 22, 23, 25, 53, 80, 110, 443, 3389, 8080)</option>
                                    <option value="web">Web Services Profile (80, 443, 8000, 8080, 8443)</option>
                                    <option value="range1024">Standard Well-Known Range (1-1024)</option>
                                </select>
                            </div>
                            <button
                                onClick={handlePortScan}
                                disabled={loading || !target}
                                className="w-full sm:w-auto px-8 py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl shadow-[0_0_20px_rgba(37,99,235,0.3)] disabled:opacity-50 disabled:shadow-none transition-all flex items-center justify-center gap-2 shrink-0 font-mono text-sm"
                            >
                                <Server className="w-4 h-4" />
                                {loading ? 'Scanning Ports...' : 'Audit Ports'}
                            </button>
                        </div>
                    </div>
                )}

                {/* 4. TRACEROUTE */}
                {subTab === 'traceroute' && (
                    <div className="flex flex-col sm:flex-row gap-3">
                        <div className="relative flex-1">
                            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                                <Route className="w-4 h-4 text-slate-500" />
                            </div>
                            <input
                                type="text"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                placeholder="Target destination (e.g., 8.8.8.8 or cloudflare.com)"
                                className="w-full pl-10 pr-4 py-3 bg-slate-900/80 border border-slate-700/80 rounded-xl text-white font-mono text-sm placeholder-slate-500 focus:border-blue-500 focus:outline-none"
                            />
                        </div>
                        <button
                            onClick={() => executeAction('traceroute', { target })}
                            disabled={loading || !target}
                            className="px-7 py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl shadow-[0_0_20px_rgba(37,99,235,0.3)] disabled:opacity-50 disabled:shadow-none transition-all flex items-center justify-center gap-2 shrink-0 font-mono text-sm"
                        >
                            <Route className="w-4 h-4" />
                            {loading ? 'Tracing Route...' : 'Map Hops'}
                        </button>
                    </div>
                )}

                {/* 5. DNS */}
                {subTab === 'dns' && (
                    <div className="flex flex-col sm:flex-row gap-3">
                        <div className="relative flex-1">
                            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                                <Globe className="w-4 h-4 text-slate-500" />
                            </div>
                            <input
                                type="text"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                placeholder="Domain name (e.g., google.com, github.com)"
                                className="w-full pl-10 pr-4 py-3 bg-slate-900/80 border border-slate-700/80 rounded-xl text-white font-mono text-sm placeholder-slate-500 focus:border-blue-500 focus:outline-none"
                            />
                        </div>
                        <button
                            onClick={() => executeAction('dns-lookup', { target })}
                            disabled={loading || !target}
                            className="px-7 py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl shadow-[0_0_20px_rgba(37,99,235,0.3)] disabled:opacity-50 disabled:shadow-none transition-all flex items-center justify-center gap-2 shrink-0 font-mono text-sm"
                        >
                            <Globe className="w-4 h-4" />
                            {loading ? 'Resolving...' : 'Query Records'}
                        </button>
                    </div>
                )}

                {/* 6. WHOIS */}
                {subTab === 'whois' && (
                    <div className="flex flex-col sm:flex-row gap-3">
                        <div className="relative flex-1">
                            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                                <FileSearch className="w-4 h-4 text-slate-500" />
                            </div>
                            <input
                                type="text"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                placeholder="Domain name (e.g., microsoft.com, bbc.co.uk)"
                                className="w-full pl-10 pr-4 py-3 bg-slate-900/80 border border-slate-700/80 rounded-xl text-white font-mono text-sm placeholder-slate-500 focus:border-blue-500 focus:outline-none"
                            />
                        </div>
                        <button
                            onClick={() => executeAction('whois', { target })}
                            disabled={loading || !target}
                            className="px-7 py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl shadow-[0_0_20px_rgba(37,99,235,0.3)] disabled:opacity-50 disabled:shadow-none transition-all flex items-center justify-center gap-2 shrink-0 font-mono text-sm"
                        >
                            <FileSearch className="w-4 h-4" />
                            {loading ? 'Querying...' : 'Lookup WHOIS'}
                        </button>
                    </div>
                )}

                {/* 7. MAC PROFILER */}
                {subTab === 'mac' && (
                    <div className="flex flex-col sm:flex-row gap-3">
                        <div className="relative flex-1">
                            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                                <Cpu className="w-4 h-4 text-slate-500" />
                            </div>
                            <input
                                type="text"
                                value={macAddress}
                                onChange={(e) => setMacAddress(e.target.value)}
                                placeholder="Hardware MAC Address (e.g., 00:1A:2B:3C:4D:5E)"
                                className="w-full pl-10 pr-4 py-3 bg-slate-900/80 border border-slate-700/80 rounded-xl text-white font-mono text-sm placeholder-slate-500 focus:border-blue-500 focus:outline-none"
                            />
                        </div>
                        <button
                            onClick={() => executeAction('mac-lookup', { mac: macAddress })}
                            disabled={loading || !macAddress}
                            className="px-7 py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl shadow-[0_0_20px_rgba(37,99,235,0.3)] disabled:opacity-50 disabled:shadow-none transition-all flex items-center justify-center gap-2 shrink-0 font-mono text-sm"
                        >
                            <Cpu className="w-4 h-4" />
                            {loading ? 'Resolving OUI...' : 'Resolve Vendor'}
                        </button>
                    </div>
                )}

                {/* 8. SUBNET CALCULATOR */}
                {subTab === 'subnet' && (
                    <div className="flex flex-col sm:flex-row gap-3">
                        <div className="relative flex-1">
                            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                                <Calculator className="w-4 h-4 text-slate-500" />
                            </div>
                            <input
                                type="text"
                                value={cidrInput}
                                onChange={(e) => setCidrInput(e.target.value)}
                                placeholder="CIDR Prefix (e.g., 192.168.1.0/24 or 10.0.0.0/16)"
                                className="w-full pl-10 pr-4 py-3 bg-slate-900/80 border border-slate-700/80 rounded-xl text-white font-mono text-sm placeholder-slate-500 focus:border-blue-500 focus:outline-none"
                            />
                        </div>
                        <button
                            onClick={() => executeAction('subnet-calc', { cidr: cidrInput })}
                            disabled={loading || !cidrInput}
                            className="px-7 py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl shadow-[0_0_20px_rgba(37,99,235,0.3)] disabled:opacity-50 disabled:shadow-none transition-all flex items-center justify-center gap-2 shrink-0 font-mono text-sm"
                        >
                            <Calculator className="w-4 h-4" />
                            {loading ? 'Calculating...' : 'Compute CIDR'}
                        </button>
                    </div>
                )}

                {/* 9. SSL INSPECTOR */}
                {subTab === 'ssl' && (
                    <div className="flex flex-col sm:flex-row gap-3">
                        <div className="relative flex-1">
                            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                                <ShieldCheck className="w-4 h-4 text-slate-500" />
                            </div>
                            <input
                                type="text"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                placeholder="Domain or Host (e.g., cloudflare.com, bank.com)"
                                className="w-full pl-10 pr-4 py-3 bg-slate-900/80 border border-slate-700/80 rounded-xl text-white font-mono text-sm placeholder-slate-500 focus:border-blue-500 focus:outline-none"
                            />
                        </div>
                        <button
                            onClick={() => executeAction('ssl-check', { target })}
                            disabled={loading || !target}
                            className="px-7 py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl shadow-[0_0_20px_rgba(37,99,235,0.3)] disabled:opacity-50 disabled:shadow-none transition-all flex items-center justify-center gap-2 shrink-0 font-mono text-sm"
                        >
                            <ShieldCheck className="w-4 h-4" />
                            {loading ? 'Inspecting...' : 'Audit TLS Cert'}
                        </button>
                    </div>
                )}
            </div>

            {/* Notifications & Output */}
            <AnimatePresence mode="wait">
                {error && (
                    <motion.div
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        className="p-4 bg-red-950/40 border border-red-500/40 text-red-300 rounded-xl font-medium text-sm mb-6 flex items-start gap-3 shadow-lg"
                    >
                        <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                        <div>
                            <span className="font-bold text-red-200 block font-mono">DIAGNOSTIC_ERROR:</span>
                            <span>{error}</span>
                        </div>
                    </motion.div>
                )}

                {loading && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                        <LoadingSpinner text="Executing diagnostics probe & correlating telemetry..." color="#60a5fa" />
                    </motion.div>
                )}

                {results && !loading && (
                    <motion.div initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.25 }} className="relative z-10 space-y-6">

                        {/* Ping Result */}
                        {subTab === 'ping' && results.status && (
                            <div className="bg-slate-950/80 p-6 rounded-2xl border border-slate-800 shadow-xl">
                                <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
                                    <div className="flex items-center gap-3">
                                        <div className={`w-3.5 h-3.5 rounded-full ${results.status === 'up' ? 'bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.8)]' : 'bg-red-500 shadow-[0_0_12px_rgba(239,68,68,0.8)]'}`}></div>
                                        <div>
                                            <span className="text-xs text-slate-500 font-mono uppercase block">Target Host</span>
                                            <h4 className="text-xl font-bold text-white font-mono">{results.host}</h4>
                                        </div>
                                    </div>
                                    <span className={`px-3 py-1 text-xs font-mono font-bold rounded-lg uppercase tracking-wider border ${results.status === 'up'
                                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                                            : 'bg-red-500/10 text-red-400 border-red-500/30'
                                        }`}>
                                        {results.status === 'up' ? '● HOST ONLINE' : '● HOST UNREACHABLE'}
                                    </span>
                                </div>

                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                    <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                        <span className="block text-xs font-mono text-slate-400 uppercase tracking-wider mb-1">Status Verdict</span>
                                        <span className={`text-lg font-bold ${results.status === 'up' ? 'text-emerald-400' : 'text-red-400'}`}>
                                            {results.status.toUpperCase()}
                                        </span>
                                    </div>
                                    <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                        <span className="block text-xs font-mono text-slate-400 uppercase tracking-wider mb-1">Round-Trip Latency (RTT)</span>
                                        <span className="text-lg font-mono font-bold text-blue-400">{results.rtt || 'Timeout'}</span>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Sweep Result */}
                        {subTab === 'sweep' && results.active_hosts && (
                            <div className="bg-slate-950/80 p-6 rounded-2xl border border-slate-800 shadow-xl">
                                <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
                                    <div>
                                        <h4 className="text-lg font-bold text-white tracking-wide">Subnet Discovery Matrix</h4>
                                        <p className="text-xs text-slate-500 font-mono">Found {results.active_hosts.length} responsive host(s)</p>
                                    </div>
                                    <span className="px-2.5 py-1 bg-blue-500/10 text-blue-400 border border-blue-500/30 text-xs font-mono rounded">
                                        {results.active_hosts.length} ONLINE
                                    </span>
                                </div>
                                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                                    {results.active_hosts.map((host, idx) => (
                                        <div key={idx} className="flex items-center justify-between p-3.5 bg-slate-900/90 rounded-xl border border-slate-800 hover:border-slate-700 transition-colors">
                                            <div className="flex items-center gap-2.5">
                                                <div className="w-2 h-2 bg-emerald-400 rounded-full shadow-[0_0_8px_rgba(52,211,153,0.6)]"></div>
                                                <span className="font-mono text-xs sm:text-sm text-slate-200 font-semibold">{host.host}</span>
                                            </div>
                                            <button
                                                onClick={() => copyToClipboard(host.host, `host-${idx}`)}
                                                className="p-1 text-slate-500 hover:text-white rounded hover:bg-slate-800 transition-colors"
                                                title="Copy IP"
                                            >
                                                {copiedKey === `host-${idx}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Port Result */}
                        {subTab === 'ports' && results.open_ports && (
                            <div className="bg-slate-950/80 p-6 rounded-2xl border border-slate-800 shadow-xl">
                                <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-5">
                                    <div>
                                        <h4 className="text-lg font-bold text-white tracking-wide">TCP Port Audit Report</h4>
                                        <p className="text-xs text-slate-500 font-mono">{results.open_ports.length} open port(s) discovered</p>
                                    </div>
                                    <span className="px-2.5 py-1 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-xs font-mono rounded">
                                        AUDIT_COMPLETE
                                    </span>
                                </div>
                                {results.open_ports.length === 0 ? (
                                    <div className="text-center py-10 text-slate-500 font-mono text-sm">
                                        No open ports identified within the selected probe scope.
                                    </div>
                                ) : (
                                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                        {results.open_ports.map((port, idx) => (
                                            <div key={idx} className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between">
                                                <div className="flex justify-between items-start mb-3">
                                                    <div>
                                                        <span className="font-mono font-bold text-blue-400 text-base">Port {port.port}</span>
                                                        <span className="block text-[11px] font-mono uppercase tracking-wider text-slate-400">{port.service || 'UNKNOWN_SERVICE'}</span>
                                                    </div>
                                                    <span className="text-[10px] px-2 py-0.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono font-bold rounded uppercase">
                                                        OPEN
                                                    </span>
                                                </div>
                                                {port.banner && (
                                                    <div className="mt-2 pt-2 border-t border-slate-800/80">
                                                        <span className="text-[10px] text-slate-500 font-mono uppercase block mb-0.5">Banner</span>
                                                        <span className="text-xs text-slate-300 font-mono break-all bg-slate-950/60 p-1.5 rounded block">{port.banner}</span>
                                                    </div>
                                                )}
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Traceroute Result */}
                        {subTab === 'traceroute' && results.hops && (
                            <div className="bg-slate-950/80 p-6 rounded-2xl border border-slate-800 shadow-xl">
                                <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
                                    <h4 className="text-lg font-bold text-white tracking-wide">Network Path Telemetry</h4>
                                    <span className="text-xs font-mono text-slate-400">{results.hops.length} Hops Identified</span>
                                </div>
                                <div className="space-y-2 font-mono text-xs max-h-96 overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-slate-800">
                                    {results.hops.map((hop, idx) => (
                                        <div key={idx} className="flex items-center gap-3 p-3 bg-slate-900/90 rounded-xl border border-slate-800/80 hover:border-slate-700 transition-colors">
                                            <span className="px-2 py-0.5 bg-blue-950/80 border border-blue-500/30 text-blue-400 font-bold rounded text-[11px] shrink-0">
                                                #{idx + 1}
                                            </span>
                                            <span className="text-slate-300 break-all">{hop}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* DNS Result */}
                        {subTab === 'dns' && results.records && (
                            <div className="bg-slate-950/80 p-6 rounded-2xl border border-slate-800 shadow-xl">
                                <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
                                    <h4 className="text-lg font-bold text-white tracking-wide">DNS Zone Records</h4>
                                    <span className="text-xs font-mono text-blue-400 bg-blue-950/60 border border-blue-500/30 px-2.5 py-1 rounded">RESOLVED</span>
                                </div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {Object.entries(results.records).map(([type, values]) => (
                                        <div key={type} className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                            <div className="flex items-center justify-between mb-2.5 border-b border-slate-800 pb-2">
                                                <span className="text-xs font-bold text-blue-400 font-mono tracking-wider">TYPE {type}</span>
                                                <span className="text-[10px] text-slate-500 font-mono">{values.length} record(s)</span>
                                            </div>
                                            {values.length > 0 ? (
                                                <ul className="space-y-1.5 mt-2">
                                                    {values.map((v, i) => (
                                                        <li key={i} className="font-mono text-xs text-slate-300 break-all flex items-center justify-between bg-slate-950/60 p-2 rounded-lg border border-slate-800/50">
                                                            <span>{v}</span>
                                                            <button
                                                                onClick={() => copyToClipboard(v, `dns-${type}-${i}`)}
                                                                className="ml-2 text-slate-500 hover:text-white"
                                                                title="Copy"
                                                            >
                                                                {copiedKey === `dns-${type}-${i}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                                                            </button>
                                                        </li>
                                                    ))}
                                                </ul>
                                            ) : (
                                                <span className="text-xs text-slate-500 italic font-mono">No {type} records configured</span>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* WHOIS Result */}
                        {subTab === 'whois' && results && (
                            <div className="bg-slate-950/80 p-6 rounded-2xl border border-slate-800 shadow-xl">
                                <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
                                    <h4 className="text-lg font-bold text-white tracking-wide flex items-center gap-2">
                                        <FileSearch className="w-5 h-5 text-blue-400" />
                                        WHOIS Registration Dossier
                                    </h4>
                                </div>

                                {results.error ? (
                                    <p className="text-red-400 bg-red-950/30 p-4 rounded-xl border border-red-500/30 font-mono text-sm">{results.error}</p>
                                ) : (
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        <div className="space-y-4">
                                            <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">Registrar</span>
                                                <span className="text-white font-semibold text-base">{results.registrar || 'N/A'}</span>
                                            </div>
                                            <div className="grid grid-cols-2 gap-4">
                                                <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                                    <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">Created</span>
                                                    <span className="text-emerald-400 font-mono text-sm">{results.creation_date || 'N/A'}</span>
                                                </div>
                                                <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                                    <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">Expires</span>
                                                    <span className="text-red-400 font-mono text-sm">{results.expiration_date || 'N/A'}</span>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-3">Authoritative Name Servers</span>
                                            {results.name_servers?.length > 0 ? (
                                                <ul className="space-y-2">
                                                    {results.name_servers.map((ns, idx) => (
                                                        <li key={idx} className="text-slate-300 font-mono text-xs flex items-center gap-2 bg-slate-950/60 p-2 rounded-lg border border-slate-800/50">
                                                            <ArrowRight className="w-3.5 h-3.5 text-blue-400" />
                                                            <span>{ns}</span>
                                                        </li>
                                                    ))}
                                                </ul>
                                            ) : (
                                                <span className="text-slate-500 italic text-xs font-mono">No Name Servers Found</span>
                                            )}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* MAC Lookup Result */}
                        {subTab === 'mac' && (
                            <div className="bg-slate-950/80 p-6 rounded-2xl border border-slate-800 shadow-xl">
                                <h4 className="text-lg font-bold text-white tracking-wide mb-4 flex items-center gap-2">
                                    <Cpu className="w-5 h-5 text-blue-400" />
                                    OUI Hardware Profile
                                </h4>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                        <span className="text-[11px] font-mono text-slate-400 uppercase block mb-1">MAC Address</span>
                                        <span className="text-white font-mono text-lg font-bold">{results.mac}</span>
                                    </div>
                                    <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                        <span className="text-[11px] font-mono text-slate-400 uppercase block mb-1">Resolved Hardware Vendor</span>
                                        <span className={`font-semibold text-lg ${results.status === 'success' ? 'text-emerald-400' : 'text-yellow-400'}`}>
                                            {results.vendor}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Subnet Calculator Result */}
                        {subTab === 'subnet' && results && (
                            <div className="bg-slate-950/80 p-6 rounded-2xl border border-slate-800 shadow-xl">
                                <h4 className="text-lg font-bold text-white tracking-wide mb-6 flex items-center gap-2">
                                    <Calculator className="w-5 h-5 text-blue-400" />
                                    Subnet CIDR Topology Breakdown
                                </h4>

                                {results.error ? (
                                    <p className="text-red-400 bg-red-950/30 p-4 rounded-xl border border-red-500/30 font-mono text-sm">
                                        Invalid Subnet CIDR format. Please provide a standard prefix like 192.168.1.0/24.
                                    </p>
                                ) : (
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                        <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">Network ID</span>
                                            <span className="text-blue-400 font-mono text-lg font-bold">{results.network_address}</span>
                                        </div>
                                        <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">Subnet Mask</span>
                                            <span className="text-white font-mono text-lg font-bold">{results.netmask}</span>
                                        </div>
                                        <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">Broadcast ID</span>
                                            <span className="text-purple-400 font-mono text-lg font-bold">{results.broadcast_address}</span>
                                        </div>

                                        <div className="md:col-span-2 p-5 bg-slate-900/90 rounded-xl border border-slate-800">
                                            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-2">Usable Host Scope</span>
                                            <span className="text-emerald-400 font-mono text-base font-bold bg-slate-950/80 p-2.5 rounded-lg border border-slate-800 block">
                                                {results.usable_range}
                                            </span>
                                        </div>
                                        <div className="p-5 bg-slate-900/90 rounded-xl border border-slate-800 flex flex-col justify-center">
                                            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">Host Capacity</span>
                                            <span className="text-white font-mono font-bold text-3xl">{results.total_hosts?.toLocaleString()}</span>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* SSL Result */}
                        {subTab === 'ssl' && results && (
                            <div className="bg-slate-950/80 p-6 rounded-2xl border border-slate-800 shadow-xl">
                                <h4 className="text-lg font-bold text-white tracking-wide mb-4 flex items-center gap-2">
                                    <ShieldCheck className="w-5 h-5 text-blue-400" />
                                    TLS/SSL Certificate Audit
                                </h4>
                                {results.error ? (
                                    <p className="text-red-400 bg-red-950/30 p-4 rounded-xl border border-red-500/30 font-mono text-sm">{results.error}</p>
                                ) : (
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                            <span className="text-[11px] font-mono text-slate-400 uppercase block mb-1">Domain Target</span>
                                            <span className="text-white font-mono font-bold text-base">{results.domain}</span>
                                        </div>
                                        <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                            <span className="text-[11px] font-mono text-slate-400 uppercase block mb-1">Certificate Authority</span>
                                            <span className="text-blue-400 font-semibold">{results.issuer}</span>
                                        </div>
                                        <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800">
                                            <span className="text-[11px] font-mono text-slate-400 uppercase block mb-1">Expiry Date</span>
                                            <span className="text-white font-mono">{results.expiry}</span>
                                        </div>
                                        <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 flex items-center justify-between">
                                            <div>
                                                <span className="text-[11px] font-mono text-slate-400 uppercase block mb-1">Security Validity</span>
                                                <span className={`text-xl font-black font-mono ${results.valid ? 'text-emerald-400' : 'text-red-400'}`}>
                                                    {results.days_left} Days Remaining
                                                </span>
                                            </div>
                                            <div className={`p-2.5 rounded-xl border ${results.valid ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-red-500/10 border-red-500/30 text-red-400'}`}>
                                                <ShieldCheck className="w-6 h-6" />
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
