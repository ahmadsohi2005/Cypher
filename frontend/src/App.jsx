import { useState, useEffect } from 'react';
import { Shield, ShieldAlert, Activity, Search, FileText, ArrowLeft, Clock } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import NetworkTool from './components/NetworkTool';
import ScannerTool from './components/ScannerTool';
import OsintTool from './components/OsintTool';
import LogAnalyzer from './components/LogAnalyzer';

export default function App() {
  const [activeTool, setActiveTool] = useState(null);
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const formatPKT = (date) => {
    return date.toLocaleString('en-PK', {
      timeZone: 'Asia/Karachi',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    });
  };

  const tools = [
    {
      id: 'network', name: 'Network Utilities', icon: Activity,
      color: 'text-blue-500', bg: 'bg-blue-500/10',
      desc: 'Ping, Port Scan, and DNS Lookup and More', status: 'active'
    },
    {
      id: 'scanner', name: 'URL Scanner', icon: ShieldAlert,
      color: 'text-red-500', bg: 'bg-red-500/10',
      desc: 'Analyze URLs against VirusTotal and Alienware OTX engines', status: 'active'
    },
    {
      id: 'osint', name: 'OSINT Intelligence', icon: Search,
      color: 'text-purple-500', bg: 'bg-purple-500/10',
      desc: 'Domain and IP footprinting and More', status: 'active'
    },
    {
      id: 'logs', name: 'Log Analyzer', icon: FileText,
      color: 'text-emerald-500', bg: 'bg-emerald-500/10',
      desc: 'Parse and visualize server logs and More', status: 'active'
    }
  ];

  return (
    <div className="min-h-screen w-full bg-slate-950 text-slate-100 font-sans selection:bg-blue-500/30">

      {/* Top Navbar - Full Width */}
      <header className="w-full border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50">
        <div className="w-full px-4 sm:px-6 lg:px-8 flex items-center justify-between h-16">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 rounded-lg border border-blue-500/20">
              <Shield className="w-6 h-6 text-blue-400" />
            </div>
            <h1 className="text-xl font-bold tracking-wide text-white">CYPHER</h1>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-2 text-xs font-mono text-purple-400 bg-purple-500/10 px-3 py-1.5 rounded border border-purple-500/20">
              <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse"></span>
              <span>"Defend the perimeter, trust nothing."</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content - Full Width */}
      <main className="w-full px-4 sm:px-6 lg:px-8 py-6">
        <AnimatePresence mode="wait">
          {!activeTool ? (
            <motion.div
              key="grid"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.3 }}
              className="w-full"
            >
              <div className="mb-8">
                <h2 className="text-3xl font-bold text-white">Select a Module</h2>
                <p className="text-slate-400 mt-1">Deploy reconnaissance and analysis tools.</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                {tools.map((tool, index) => {
                  const Icon = tool.icon;
                  return (
                    <motion.div
                      key={tool.id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1 }}
                      onClick={() => tool.status === 'active' && setActiveTool(tool.id)}
                      className={`group relative p-6 rounded-2xl border transition-all duration-300 overflow-hidden min-h-[200px] flex flex-col
                        ${tool.status === 'active'
                          ? 'bg-slate-900/80 border-slate-800 hover:border-slate-600 cursor-pointer hover:shadow-2xl hover:shadow-blue-500/10 hover:scale-[1.02]'
                          : 'bg-slate-900/50 border-slate-800/50 cursor-not-allowed opacity-60'} 
                      `}
                    >
                      <div className="flex items-start justify-between mb-4">
                        <div className={`p-3 rounded-xl ${tool.bg}`}>
                          <Icon className={`w-7 h-7 ${tool.color}`} />
                        </div>
                        {tool.status === 'locked' && (
                          <span className="text-[10px] font-bold px-2 py-1 bg-slate-800 text-slate-400 rounded uppercase tracking-widest">
                            Coming Soon
                          </span>
                        )}
                      </div>
                      <h3 className="text-xl font-bold text-white mb-2 group-hover:text-blue-400 transition-colors">
                        {tool.name}
                      </h3>
                      <p className="text-sm text-slate-400 leading-relaxed flex-1">
                        {tool.desc}
                      </p>
                      {tool.status === 'active' && (
                        <div className="mt-4 text-xs text-blue-400/60 group-hover:text-blue-400 transition-colors">
                          Click to launch →
                        </div>
                      )}
                    </motion.div>
                  );
                })}
              </div>
            </motion.div>
          ) : (
            <motion.div
              key="tool"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ duration: 0.3 }}
              className="w-full"
            >
              <button
                onClick={() => setActiveTool(null)}
                className="group flex items-center gap-2 text-sm text-slate-400 hover:text-white font-medium mb-6 transition-colors"
              >
                <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" />
                Back to Dashboard
              </button>

              <div className="w-full">
                {activeTool === 'network' && <NetworkTool />}
                {activeTool === 'scanner' && <ScannerTool />}
                {activeTool === 'osint' && <OsintTool />}
                {activeTool === 'logs' && <LogAnalyzer />}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}
