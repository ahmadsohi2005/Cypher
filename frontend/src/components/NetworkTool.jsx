import { useState, useEffect } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import LoadingSpinner from './LoadingSpinner';
import { saveActivity } from '../utils/historyManager';

export default function NetworkTool() {
    const [subTab, setSubTab] = useState('ping');
    const [target, setTarget] = useState('');

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

    return (
        <div className="bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-6 text-slate-200">
            <h2 className="text-2xl font-bold text-white mb-6">Network Diagnostics & Discovery</h2>

            {/* Sub-navigation tabs */}
            <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-4 mb-6">
                {[
                    { id: 'ping', label: 'Ping' },
                    { id: 'sweep', label: 'Ping Sweep' },
                    { id: 'ports', label: 'Port Scanner' },
                    // { id: 'traceroute', label: 'Traceroute' },
                    { id: 'dns', label: 'DNS Lookup' },
                    { id: 'whois', label: 'WHOIS Lookup' },
                    { id: 'mac', label: 'MAC Profiler' },
                    { id: 'subnet', label: 'Subnet Calc' },
                    { id: 'ssl', label: 'SSL Inspector' }
                ].map((tab) => (
                    <button
                        key={tab.id}
                        onClick={() => setSubTab(tab.id)}
                        className={`px-4 py-2 text-sm font-semibold rounded-lg transition-all ${subTab === tab.id
                            ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
                            : 'bg-slate-800 text-slate-400 hover:bg-slate-700 hover:text-white'
                            }`}
                    >
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* Inputs Area */}
            <div className="space-y-4 mb-8">

                {/* 1. PING */}
                {subTab === 'ping' && (
                    <div className="flex gap-3">
                        <input
                            type="text" value={target} onChange={(e) => setTarget(e.target.value)}
                            placeholder="Enter target (e.g., google.com)"
                            className="flex-1 p-3 bg-slate-950 border border-slate-700 rounded-lg text-white focus:border-blue-500 focus:outline-none"
                        />
                        <button onClick={() => executeAction('ping', { target })} disabled={loading || !target}
                            className="px-6 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-500 disabled:opacity-50 transition-colors">
                            {loading ? 'Pinging...' : 'Send Ping'}
                        </button>
                    </div>
                )}

                {/* 2. SWEEP */}
                {subTab === 'sweep' && (
                    <div className="flex flex-col gap-4">
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                            <input type="text" value={baseIp} onChange={(e) => setBaseIp(e.target.value)} placeholder="Base IP (e.g., 192.168.1.)" className="p-3 bg-slate-950 border border-slate-700 rounded-lg text-white" />
                            <input type="number" value={startIp} onChange={(e) => setStartIp(Number(e.target.value))} placeholder="Start" className="p-3 bg-slate-950 border border-slate-700 rounded-lg text-white" />
                            <input type="number" value={endIp} onChange={(e) => setEndIp(Number(e.target.value))} placeholder="End" className="p-3 bg-slate-950 border border-slate-700 rounded-lg text-white" />
                        </div>
                        <button onClick={() => executeAction('ping-sweep', { base_ip: baseIp, start: startIp, end: endIp })} disabled={loading || !baseIp}
                            className="w-full py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-500 disabled:opacity-50 transition-colors">
                            {loading ? 'Sweeping Subnet...' : 'Run Ping Sweep'}
                        </button>
                    </div>
                )}

                {/* 3. PORTS */}
                {subTab === 'ports' && (
                    <div className="flex flex-col gap-4">
                        <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="Target IP or Domain" className="p-3 bg-slate-950 border border-slate-700 rounded-lg text-white w-full" />
                        <div className="flex items-center gap-4">
                            <select value={portProfile} onChange={(e) => setPortProfile(e.target.value)} className="flex-1 p-3 bg-slate-950 border border-slate-700 rounded-lg text-white">
                                <option value="top10">Top 10 Common Ports</option>
                                <option value="web">Web Services (HTTP/HTTPS/Alt)</option>
                                <option value="range1024">Standard Range (1-1024)</option>
                            </select>
                            <button onClick={handlePortScan} disabled={loading || !target}
                                className="px-6 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-500 disabled:opacity-50 transition-colors">
                                {loading ? 'Scanning Ports...' : 'Start Scan'}
                            </button>
                        </div>
                    </div>
                )}

               {/* Traceroute Feature removed -- will be added later */}

                {/* 5. DNS */}
                {subTab === 'dns' && (
                    <div className="flex gap-3">
                        <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="Domain name (e.g., google.com)" className="flex-1 p-3 bg-slate-950 border border-slate-700 rounded-lg text-white" />
                        <button onClick={() => executeAction('dns-lookup', { target })} disabled={loading || !target}
                            className="px-6 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-500 disabled:opacity-50 transition-colors">
                            {loading ? 'Querying DNS...' : 'Lookup Records'}
                        </button>
                    </div>
                )}

                {/* 6. WHOIS */}
                {subTab === 'whois' && (
                    <div className="flex gap-3">
                        <input
                            type="text" value={target} onChange={(e) => setTarget(e.target.value)}
                            placeholder="Domain name (e.g., github.com)"
                            className="flex-1 p-3 bg-slate-950 border border-slate-700 rounded-lg text-white focus:border-blue-500 focus:outline-none"
                        />
                        <button onClick={() => executeAction('whois', { target })} disabled={loading || !target}
                            className="px-6 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-500 disabled:opacity-50 transition-colors">
                            {loading ? 'Fetching WHOIS...' : 'Lookup WHOIS'}
                        </button>
                    </div>
                )}

                {/* 7. MAC PROFILER */}
                {subTab === 'mac' && (
                    <div className="flex gap-3">
                        <input
                            type="text" value={macAddress} onChange={(e) => setMacAddress(e.target.value)}
                            placeholder="MAC Address (e.g., 00:1A:2B:3C:4D:5E)"
                            className="flex-1 p-3 bg-slate-950 border border-slate-700 rounded-lg text-white focus:border-blue-500 focus:outline-none"
                        />
                        <button onClick={() => executeAction('mac-lookup', { mac: macAddress })} disabled={loading || !macAddress}
                            className="px-6 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-500 disabled:opacity-50 transition-colors">
                            {loading ? 'Identifying...' : 'Lookup Vendor'}
                        </button>
                    </div>
                )}

                {/* 8. SUBNET CALCULATOR */}
                {subTab === 'subnet' && (
                    <div className="flex gap-3">
                        <input
                            type="text" value={cidrInput} onChange={(e) => setCidrInput(e.target.value)}
                            placeholder="Subnet CIDR (e.g., 192.168.1.0/24 or 10.0.0.0/16)"
                            className="flex-1 p-3 bg-slate-950 border border-slate-700 rounded-lg text-white focus:border-blue-500 focus:outline-none"
                        />
                        <button onClick={() => executeAction('subnet-calc', { cidr: cidrInput })} disabled={loading || !cidrInput}
                            className="px-6 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-500 disabled:opacity-50 transition-colors">
                            {loading ? 'Calculating...' : 'Calculate'}
                        </button>
                    </div>
                )}

                {/* 9. SSL INSPECTOR */}
                {subTab === 'ssl' && (
                    <div className="flex gap-3">
                        <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="Domain (e.g., github.com)" className="flex-1 p-3 bg-slate-950 border border-slate-700 rounded-lg text-white focus:border-blue-500 focus:outline-none" />
                        <button onClick={() => executeAction('ssl-check', { target })} disabled={loading || !target} className="px-6 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-500 disabled:opacity-50 transition-colors">
                            {loading ? 'Inspecting...' : 'Check SSL'}
                        </button>
                    </div>
                )}

            </div>

            {/* Notifications & Output */}
            <AnimatePresence mode="wait">
                {error && (
                    <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="p-4 bg-red-900/30 border border-red-500/50 text-red-400 rounded-lg font-medium mb-6">
                        {error}
                    </motion.div>
                )}

                {loading && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                        <LoadingSpinner text="Executing diagnostics..." color="#60a5fa" />
                    </motion.div>
                )}

                {results && !loading && (
                    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="mt-4">

                        {/* Ping Result */}
                        {subTab === 'ping' && results.status && (
                            <div className="bg-slate-950 p-6 rounded-xl border border-slate-800">
                                <div className="flex items-center gap-3 mb-6">
                                    <div className={`w-3 h-3 rounded-full ${results.status === 'up' ? 'bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]' : 'bg-red-500'}`}></div>
                                    <h4 className="text-xl font-bold text-white">{results.host}</h4>
                                </div>
                                <div className="grid grid-cols-2 gap-4">
                                    <div className="p-4 bg-slate-900 rounded-lg border border-slate-800/50">
                                        <span className="block text-xs text-slate-500 uppercase mb-1">Status</span>
                                        <span className={`text-lg font-semibold ${results.status === 'up' ? 'text-emerald-400' : 'text-red-400'}`}>
                                            {results.status.toUpperCase()}
                                        </span>
                                    </div>
                                    <div className="p-4 bg-slate-900 rounded-lg border border-slate-800/50">
                                        <span className="block text-xs text-slate-500 uppercase mb-1">Response Time (RTT)</span>
                                        <span className="text-lg font-mono text-blue-400">{results.rtt || 'Timeout'}</span>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Sweep Result */}
                        {subTab === 'sweep' && results.active_hosts && (
    <div className="bg-slate-950 p-6 rounded-xl border border-slate-800">
        <h4 className="text-lg font-bold text-white mb-4">Active Hosts: {results.active_hosts.length}</h4>
        
        {/* The Map Loop Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
            {results.active_hosts.map((host, idx) => (
                <div key={idx} className="flex items-center gap-2 p-3 bg-slate-900 rounded border border-slate-800">
                    <div className="w-2 h-2 bg-emerald-500 rounded-full"></div>
                    <span className="font-mono text-sm text-slate-300">{host.host}</span>
                </div>
            ))}
        </div>

        {/* The Note placed safely outside the loop */}
        <p className="text-xs text-yellow-400">
            Note: Because this tool is cloud-hosted, scanning private ranges (like 192.168.x.x) will sweep the server's internal network, not your local connection.
        </p>
    </div>
)}

                        {/* Port Result */}
                        {subTab === 'ports' && results.open_ports && (
                            <div className="bg-slate-950 p-6 rounded-xl border border-slate-800">
                                <h4 className="text-lg font-bold text-white mb-4">Open TCP Ports</h4>
                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                    {results.open_ports.map((port, idx) => (
                                        <div key={idx} className="p-4 bg-slate-900 rounded border border-slate-800">
                                            <div className="flex justify-between items-center mb-2">
                                                <div className="flex flex-col">
                                                    <span className="font-mono font-bold text-blue-400">Port {port.port}</span>
                                                    <span className="text-[10px] uppercase tracking-wider text-slate-500">{port.service || 'UNKNOWN'}</span>
                                                </div>
                                                <span className="text-xs px-2 py-1 bg-emerald-500/10 text-emerald-400 rounded">OPEN</span>
                                            </div>
                                            <span className="text-xs text-slate-400 font-mono break-all">{port.banner}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Traceroute Result will be added later -- not working*/}

                        {/* DNS Result */}
                        {subTab === 'dns' && results.records && (
                            <div className="bg-slate-950 p-6 rounded-xl border border-slate-800">
                                <h4 className="text-lg font-bold text-white mb-4">DNS Records</h4>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {Object.entries(results.records).map(([type, values]) => (
                                        <div key={type} className="p-4 bg-slate-900 rounded border border-slate-800">
                                            <span className="text-xs font-bold text-blue-400 mb-2 block border-b border-slate-700 pb-1">TYPE {type}</span>
                                            {values.length > 0 ? (
                                                <ul className="space-y-1 mt-2">
                                                    {values.map((v, i) => <li key={i} className="font-mono text-sm text-slate-300 break-all">{v}</li>)}
                                                </ul>
                                            ) : (
                                                <span className="text-xs text-slate-500 italic">No records</span>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* WHOIS Result */}
                        {subTab === 'whois' && results && (
                            <div className="bg-slate-950 p-6 rounded-xl border border-slate-800">
                                <h4 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
                                    <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                                    WHOIS Registration Data
                                </h4>

                                {results.error ? (
                                    <p className="text-red-400 bg-red-900/20 p-4 rounded-lg border border-red-500/20">{results.error}</p>
                                ) : (
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        <div className="space-y-4">
                                            <div className="p-4 bg-slate-900 rounded-lg border border-slate-800">
                                                <span className="text-xs text-slate-500 uppercase tracking-wider block mb-1">Registrar</span>
                                                <span className="text-white font-medium text-lg">{results.registrar || 'N/A'}</span>
                                            </div>
                                            <div className="grid grid-cols-2 gap-4">
                                                <div className="p-4 bg-slate-900 rounded-lg border border-slate-800">
                                                    <span className="text-xs text-slate-500 uppercase tracking-wider block mb-1">Registered</span>
                                                    <span className="text-emerald-400 font-mono">{results.creation_date}</span>
                                                </div>
                                                <div className="p-4 bg-slate-900 rounded-lg border border-slate-800">
                                                    <span className="text-xs text-slate-500 uppercase tracking-wider block mb-1">Expires</span>
                                                    <span className="text-red-400 font-mono">{results.expiration_date}</span>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="space-y-4">
                                            <div className="p-4 bg-slate-900 rounded-lg border border-slate-800 h-full">
                                                <span className="text-xs text-slate-500 uppercase tracking-wider block mb-3">Name Servers</span>
                                                {results.name_servers?.length > 0 ? (
                                                    <ul className="space-y-2">
                                                        {results.name_servers.map((ns, idx) => (
                                                            <li key={idx} className="text-slate-300 font-mono text-sm flex items-center gap-2">
                                                                <span className="text-slate-600">→</span> {ns}
                                                            </li>
                                                        ))}
                                                    </ul>
                                                ) : (
                                                    <span className="text-slate-500 italic text-sm">No Name Servers Found</span>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* MAC Lookup Result */}
                        {subTab === 'mac' && (
                            <div className="bg-slate-950 p-6 rounded-xl border border-slate-800">
                                <h4 className="text-lg font-bold text-white mb-4">OUI / Vendor Identification</h4>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div className="p-4 bg-slate-900 rounded border border-slate-800">
                                        <span className="text-xs text-slate-500 uppercase block mb-1">MAC Address</span>
                                        <span className="text-white font-mono">{results.mac}</span>
                                    </div>
                                    <div className="p-4 bg-slate-900 rounded border border-slate-800">
                                        <span className="text-xs text-slate-500 uppercase block mb-1">Hardware Vendor</span>
                                        <span className={`font-semibold ${results.status === 'success' ? 'text-emerald-400' : 'text-yellow-400'}`}>
                                            {results.vendor}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Subnet Calculator Result */}
                        {subTab === 'subnet' && results && (
                            <div className="bg-slate-950 p-6 rounded-xl border border-slate-800">
                                <h4 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
                                    <div className="w-2 h-2 bg-emerald-500 rounded-full"></div>
                                    Subnet Topology Breakdown
                                </h4>

                                {results.error ? (
                                    <p className="text-red-400 bg-red-900/20 p-4 rounded-lg border border-red-500/20">Invalid Subnet CIDR format. Please use format like 192.168.1.0/24</p>
                                ) : (
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                        <div className="p-4 bg-slate-900 rounded-lg border border-slate-800 flex flex-col justify-center">
                                            <span className="text-xs text-slate-500 uppercase tracking-wider block mb-1">Network Address</span>
                                            <span className="text-blue-400 font-mono text-xl">{results.network_address}</span>
                                        </div>
                                        <div className="p-4 bg-slate-900 rounded-lg border border-slate-800 flex flex-col justify-center">
                                            <span className="text-xs text-slate-500 uppercase tracking-wider block mb-1">Subnet Mask</span>
                                            <span className="text-white font-mono text-xl">{results.netmask}</span>
                                        </div>
                                        <div className="p-4 bg-slate-900 rounded-lg border border-slate-800 flex flex-col justify-center">
                                            <span className="text-xs text-slate-500 uppercase tracking-wider block mb-1">Broadcast Address</span>
                                            <span className="text-purple-400 font-mono text-xl">{results.broadcast_address}</span>
                                        </div>

                                        <div className="md:col-span-2 p-5 bg-slate-900 rounded-lg border border-slate-800">
                                            <span className="text-xs text-slate-500 uppercase tracking-wider block mb-2">Usable Host IP Range</span>
                                            <span className="text-emerald-400 font-mono text-lg">{results.usable_range}</span>
                                        </div>
                                        <div className="p-5 bg-slate-900 rounded-lg border border-slate-800 flex flex-col justify-center">
                                            <span className="text-xs text-slate-500 uppercase tracking-wider block mb-1">Total Usable Hosts</span>
                                            <span className="text-white font-bold text-3xl">{results.total_hosts.toLocaleString()}</span>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* SSL Result */}
                        {subTab === 'ssl' && results && (
                            <div className="bg-slate-950 p-6 rounded-xl border border-slate-800">
                                <h4 className="text-lg font-bold text-white mb-4">TLS/SSL Certificate Details</h4>
                                {results.error ? (
                                    <p className="text-red-400 bg-red-900/20 p-4 rounded-lg border border-red-500/20">{results.error}</p>
                                ) : (
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div className="p-4 bg-slate-900 rounded border border-slate-800">
                                            <span className="text-xs text-slate-500 uppercase block mb-1">Target Domain</span>
                                            <span className="text-white font-mono">{results.domain}</span>
                                        </div>
                                        <div className="p-4 bg-slate-900 rounded border border-slate-800">
                                            <span className="text-xs text-slate-500 uppercase block mb-1">Certificate Authority (Issuer)</span>
                                            <span className="text-blue-400 font-semibold">{results.issuer}</span>
                                        </div>
                                        <div className="p-4 bg-slate-900 rounded border border-slate-800">
                                            <span className="text-xs text-slate-500 uppercase block mb-1">Expiration Date</span>
                                            <span className="text-white font-mono">{results.expiry}</span>
                                        </div>
                                        <div className="p-4 bg-slate-900 rounded border border-slate-800 flex items-center justify-between">
                                            <div>
                                                <span className="text-xs text-slate-500 uppercase block mb-1">Validity Status</span>
                                                <span className={`text-xl font-black ${results.valid ? 'text-emerald-400' : 'text-red-400'}`}>
                                                    {results.days_left} Days Left
                                                </span>
                                            </div>
                                            <div className={`p-2 rounded-full ${results.valid ? 'bg-emerald-500/20' : 'bg-red-500/20'}`}>
                                                {results.valid ? '✅' : '🚨'}
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
