import { useState, useEffect, useCallback, useRef } from 'react';
import { Shield, ShieldAlert, Activity, Search, FileText, ArrowLeft, Clock, LogOut } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import NetworkTool from './components/NetworkTool';
import ScannerTool from './components/ScannerTool';
import OsintTool from './components/OsintTool';
import LogAnalyzer from './components/LogAnalyzer';
import ActivitySidebar from './components/ActivitySidebar';
import Auth from './components/Auth';
import ResetPasswordModal from './components/ResetPasswordModal';
import { getHistory, clearHistory } from './utils/historyManager';
import { supabase } from './utils/supabaseClient';

const INACTIVITY_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

export default function App() {
  const [session, setSession] = useState(null);
  const [activeTool, setActiveTool] = useState(null);
  const [time, setTime] = useState(new Date());
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [historyData, setHistoryData] = useState([]);
  const [sessionExpiredMsg, setSessionExpiredMsg] = useState('');
  const [isResetPasswordOpen, setIsResetPasswordOpen] = useState(false);

  const lastActivityRef = useRef(Date.now());

  // Handle automatic logout on inactivity
  const handleInactivityLogout = useCallback(async () => {
    await supabase.auth.signOut();
    setSession(null);
    setSessionExpiredMsg('Security policy enforced: Session expired due to 30 minutes of inactivity.');
  }, []);

  // Update last activity timestamp on user interactions
  const recordActivity = useCallback(() => {
    lastActivityRef.current = Date.now();
  }, []);

  // Initial Auth & Recovery listeners
  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
    });

    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, newSession) => {
      if (event === 'PASSWORD_RECOVERY') {
        setIsResetPasswordOpen(true);
      }
      setSession(newSession);
    });

    // Check if URL hash contains recovery token
    if (window.location.hash && window.location.hash.includes('type=recovery')) {
      setIsResetPasswordOpen(true);
    }

    return () => subscription.unsubscribe();
  }, []);

  // 30-Minute Inactivity Watcher
  useEffect(() => {
    if (!session) return;

    // Reset last activity timer upon login
    lastActivityRef.current = Date.now();

    const activityEvents = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click'];
    activityEvents.forEach((event) => {
      window.addEventListener(event, recordActivity, { passive: true });
    });

    // Check inactivity periodically
    const inactivityInterval = setInterval(() => {
      const now = Date.now();
      if (now - lastActivityRef.current >= INACTIVITY_TIMEOUT_MS) {
        handleInactivityLogout();
      }
    }, 15000); // check every 15 seconds

    return () => {
      activityEvents.forEach((event) => {
        window.removeEventListener(event, recordActivity);
      });
      clearInterval(inactivityInterval);
    };
  }, [session, handleInactivityLogout, recordActivity]);

  useEffect(() => {
    if (isSidebarOpen && session?.user?.id) {
      getHistory(session.user.id).then(data => setHistoryData(data));
    }
  }, [isSidebarOpen, session]);

  const handleClearHistory = async () => {
    if (session?.user?.id) {
      await clearHistory(session.user.id);
      setHistoryData([]);
    }
  };

  const handleLogout = async () => {
    setSessionExpiredMsg('');
    await supabase.auth.signOut();
    setSession(null);
  };

  const handleSelectEntry = (entry) => {
    const moduleMap = {
      'network': 'network',
      'osint': 'osint',
      'logs': 'logs',
      'log analyzer': 'logs',
      'scanner': 'scanner',
      'url scanner': 'scanner'
    };
    const mod = entry.module?.toLowerCase();
    if (mod && moduleMap[mod]) {
      setActiveTool(moduleMap[mod]);
      setIsSidebarOpen(false);
    }
  };

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Tools array updated for a sleek terminal readout style
  const tools = [
    {
      id: 'network', name: 'Network Utilities', icon: Activity,
      color: 'text-blue-400', glow: 'from-blue-500',
      quote: '"Let\'s see their network."',
      readout: ['* PING SWEEP', '* PORT SCAN', '* DNS PULL'],
      status: 'active'
    },
    {
      id: 'scanner', name: 'URL Scanner', icon: ShieldAlert,
      color: 'text-red-400', glow: 'from-red-500',
      quote: '"Examine the bait."',
      readout: ['* VIRUS TOTAL', '* ALIEN VAULT', '* PAYLOAD'],
      status: 'active'
    },
    {
      id: 'osint', name: 'OSINT Intelligence', icon: Search,
      color: 'text-purple-400', glow: 'from-purple-500',
      quote: '"I know exactly where they are."',
      readout: ['* DOMAIN MAP', '* IP TRACK', '* BREACHES'],
      status: 'active'
    },
    {
      id: 'logs', name: 'Log Analyzer', icon: FileText,
      color: 'text-emerald-400', glow: 'from-emerald-500',
      quote: '"Read their footsteps."',
      readout: ['* SERVER LOGS', '* SIGNATURES', '* ANOMALIES'],
      status: 'active'
    }
  ];

  if (!session) {
    return (
      <>
        <Auth
          onLogin={(newSession) => {
            setSessionExpiredMsg('');
            setSession(newSession);
          }}
          sessionExpiredMessage={sessionExpiredMsg}
        />
        <ResetPasswordModal
          isOpen={isResetPasswordOpen}
          onClose={() => setIsResetPasswordOpen(false)}
          onSuccess={() => {
            setIsResetPasswordOpen(false);
          }}
        />
      </>
    );
  }

  return (
    <div className="min-h-screen w-full bg-slate-950 text-slate-100 font-sans selection:bg-blue-500/30 relative">

      {/* Grid Background Overlay */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:32px_32px] pointer-events-none"></div>

      {/* Top Navbar */}
      <header className="w-full border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50 relative">
        <div className="w-full px-4 sm:px-6 lg:px-8 flex items-center justify-between h-16">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 rounded border border-blue-500/30 shadow-[0_0_15px_rgba(59,130,246,0.15)]">
              <Shield className="w-6 h-6 text-blue-400" />
            </div>
            <h1 className="text-xl font-bold tracking-widest text-white font-mono">CYPHER</h1>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden md:flex items-center gap-2 text-xs font-mono text-cyan-400 bg-cyan-950/30 px-3 py-1.5 rounded border border-cyan-800/50">
              <span className="w-2 h-2 rounded-sm bg-cyan-400 animate-pulse"></span>
              <span>"Defend the perimeter, trust nothing."</span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setIsSidebarOpen(true)}
                className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded border border-slate-800 hover:border-slate-700 text-sm font-semibold transition-all shadow-md font-mono"
              >
                <Clock className="w-4 h-4 text-blue-400" />
                <span className="hidden sm:inline">Activity Log</span>
              </button>

              <button
                onClick={handleLogout}
                className="flex items-center gap-2 px-3 py-1.5 bg-red-950/30 hover:bg-red-900/40 text-red-400 rounded border border-red-900/50 text-sm font-semibold transition-all font-mono"
                title="Sign Out"
              >
                <LogOut className="w-4 h-4" />
                <span className="hidden sm:inline">Logout</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="w-full px-4 sm:px-6 lg:px-8 py-8 relative z-10">
        <AnimatePresence mode="wait">
          {!activeTool ? (
            <motion.div
              key="grid"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.98 }}
              transition={{ duration: 0.3 }}
              className="w-full"
            >
              <div className="mb-10">
                <h2 className="text-3xl font-bold text-white tracking-wide font-mono">SYSTEM MODULES</h2>
                <p className="text-slate-400 mt-2 font-mono text-sm">Awaiting directive. Select a tool to initialize scan.</p>
              </div>

              {/* TACTICAL GRID */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {tools.map((tool, index) => {
                  const Icon = tool.icon;
                  return (
                    <motion.div
                      key={tool.id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1 }}
                      onClick={() => tool.status === 'active' && setActiveTool(tool.id)}
                      className={`group relative flex flex-col p-6 bg-slate-900/40 backdrop-blur-sm border transition-all duration-300 overflow-hidden min-h-[280px]
                        ${tool.status === 'active'
                          ? 'border-slate-800 hover:border-slate-600 cursor-pointer hover:bg-slate-900/80 hover:shadow-[0_0_30px_rgba(0,0,0,0.5)]'
                          : 'border-slate-800/50 cursor-not-allowed opacity-50'} 
                      `}
                    >
                      {/* Top Accent Line */}
                      <div className={`absolute top-0 left-0 w-full h-1 bg-gradient-to-r ${tool.glow} to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300`}></div>

                      <div className="flex items-start justify-between mb-6">
                        <div className="text-slate-500 group-hover:text-white transition-colors duration-300">
                          <Icon className={`w-8 h-8 ${tool.color}`} />
                        </div>
                        {tool.status === 'locked' && (
                          <span className="text-[10px] font-bold px-2 py-1 bg-slate-800/80 text-slate-400 rounded-sm uppercase tracking-widest border border-slate-700">
                            OFFLINE
                          </span>
                        )}
                      </div>

                      <h3 className="text-xl font-bold text-white tracking-wide mb-1 group-hover:text-white transition-colors font-mono">
                        {tool.name}
                      </h3>
                      <p className="text-sm text-slate-500 italic mb-6">
                        {tool.quote}
                      </p>

                      {/* Terminal Readout */}
                      <div className="flex flex-col text-left gap-1.5 mb-8 flex-grow font-mono text-xs text-slate-600 group-hover:text-slate-400 transition-colors">
                        {tool.readout.map((line, rIdx) => (
                          <div key={rIdx}>{line}</div>
                        ))}
                      </div>

                      {tool.status === 'active' && (
                        <div className="text-sm font-mono font-bold text-slate-600 group-hover:text-blue-400 flex items-center gap-2 mt-auto transition-colors">
                          [ INITIALIZE ]
                          <span className="group-hover:translate-x-1 transition-transform">→</span>
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
                className="group flex items-center gap-2 text-sm text-slate-400 hover:text-white font-mono uppercase tracking-wider mb-8 transition-colors"
              >
                <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" />
                Abort / Return
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

      <ActivitySidebar
        isOpen={isSidebarOpen}
        onClose={() => setIsSidebarOpen(false)}
        history={historyData}
        onClear={handleClearHistory}
        onSelectEntry={handleSelectEntry}
      />

      <ResetPasswordModal
        isOpen={isResetPasswordOpen}
        onClose={() => setIsResetPasswordOpen(false)}
        onSuccess={() => setIsResetPasswordOpen(false)}
      />
    </div>
  );
}
