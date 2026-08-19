import React, { useState } from 'react';

const MODULE_COLORS = {
    'Network': 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    'OSINT': 'bg-purple-500/10 text-purple-400 border-purple-500/20',
    'Log Analyzer': 'bg-red-500/10 text-red-400 border-red-500/20',
    'URL Scanner': 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
};

// Added a default fallback of "history = []" so it never crashes if data is null
export default function ActivitySidebar({ isOpen, onClose, history = [] }) {
    const [filter, setFilter] = useState('all');

    // Make absolutely sure safeHistory is an array before trying to filter or map it
    const safeHistory = Array.isArray(history) ? history : [];

    const filteredHistory = filter === 'all'
        ? safeHistory
        : safeHistory.filter(item => item.module.toLowerCase() === filter.toLowerCase());

    const formatTime = (isoString) => {
        const date = new Date(isoString);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    };

    return (
        <>
            {isOpen && <div onClick={onClose} className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 transition-opacity" />}

            <aside className={`fixed top-0 left-0 h-full w-80 sm:w-96 bg-slate-950 border-r border-slate-800 z-50 transform transition-transform duration-300 ease-in-out flex flex-col ${isOpen ? 'translate-x-0' : '-translate-x-full'}`}>

                <div className="p-4 border-b border-slate-800 flex items-center justify-between">
                    <div>
                        <h3 className="text-lg font-bold text-white">Investigation History</h3>
                        <p className="text-xs text-slate-500">Recent scans and diagnostic events</p>
                    </div>
                    <button onClick={onClose} className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors">✕</button>
                </div>

                <div className="flex gap-1.5 p-3 border-b border-slate-800/80 overflow-x-auto text-xs">
                    {['all', 'network', 'osint', 'log analyzer', 'url scanner'].map((tab) => (
                        <button
                            key={tab}
                            onClick={() => setFilter(tab)}
                            className={`px-2.5 py-1 rounded-md capitalize whitespace-nowrap transition-colors ${filter === tab ? 'bg-blue-600 text-white font-medium' : 'bg-slate-900 text-slate-400 hover:bg-slate-800'}`}
                        >
                            {tab}
                        </button>
                    ))}
                </div>

                <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
                    {filteredHistory.length === 0 ? (
                        <div className="text-center py-16 text-slate-600 text-sm">No activity recorded yet.</div>
                    ) : (
                        filteredHistory.map((item) => (
                            <div key={item.id} className="p-3 bg-slate-900/90 border border-slate-800 rounded-lg">
                                <div className="flex items-center justify-between mb-1.5">
                                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-semibold ${MODULE_COLORS[item.module] || 'bg-slate-800 text-slate-300'}`}>
                                        {item.module}
                                    </span>
                                    <span className="text-[11px] text-slate-500 font-mono">
                                        {formatTime(item.created_at)}
                                    </span>
                                </div>
                                <div className="text-sm font-semibold text-slate-200 truncate">
                                    {item.action}: <span className="font-mono font-normal text-slate-400">{item.target}</span>
                                </div>
                                <p className="text-xs text-slate-500 mt-1 truncate">{item.summary}</p>
                            </div>
                        ))
                    )}
                </div>
            </aside>
        </>
    );
}