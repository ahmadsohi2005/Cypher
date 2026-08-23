import { useState, useEffect } from 'react';
import { supabase } from '../utils/supabaseClient';
import { Shield, KeyRound, Mail, AlertTriangle, CheckCircle2, Lock, ArrowLeft, Clock } from 'lucide-react';

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_SECONDS = 300; // 5 minutes

export default function Auth({ onLogin, sessionExpiredMessage = '' }) {
    const [mode, setMode] = useState('login'); // 'login' | 'signup' | 'forgot'
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [successMessage, setSuccessMessage] = useState('');
    const [loading, setLoading] = useState(false);

    // Rate Limiting / Brute Force State
    const [remainingAttempts, setRemainingAttempts] = useState(MAX_FAILED_ATTEMPTS);
    const [lockoutTimer, setLockoutTimer] = useState(0);

    // Check existing lockout on load or email change
    useEffect(() => {
        checkLockout();
    }, [email]);

    // Countdown interval for lockout timer
    useEffect(() => {
        let timer = null;
        if (lockoutTimer > 0) {
            timer = setInterval(() => {
                setLockoutTimer((prev) => {
                    if (prev <= 1) {
                        clearInterval(timer);
                        return 0;
                    }
                    return prev - 1;
                });
            }, 1000);
        }
        return () => {
            if (timer) clearInterval(timer);
        };
    }, [lockoutTimer]);

    const getStorageKey = () => `cypher_rate_limit_${(email || 'anonymous').trim().toLowerCase()}`;

    const checkLockout = () => {
        try {
            const raw = localStorage.getItem(getStorageKey());
            if (raw) {
                const data = JSON.parse(raw);
                const now = Math.floor(Date.now() / 1000);
                if (data.lockedUntil && data.lockedUntil > now) {
                    setLockoutTimer(data.lockedUntil - now);
                    setRemainingAttempts(0);
                    return true;
                } else if (data.lockedUntil && data.lockedUntil <= now) {
                    // Lockout expired, reset attempts
                    localStorage.removeItem(getStorageKey());
                    setRemainingAttempts(MAX_FAILED_ATTEMPTS);
                    setLockoutTimer(0);
                } else {
                    const attempts = data.attempts || 0;
                    setRemainingAttempts(Math.max(0, MAX_FAILED_ATTEMPTS - attempts));
                }
            } else {
                setRemainingAttempts(MAX_FAILED_ATTEMPTS);
                setLockoutTimer(0);
            }
        } catch (e) {
            console.error('Failed to read rate limiting state:', e);
        }
        return false;
    };

    const recordFailedAttempt = () => {
        try {
            const key = getStorageKey();
            const raw = localStorage.getItem(key);
            const now = Math.floor(Date.now() / 1000);
            let attempts = 1;

            if (raw) {
                const data = JSON.parse(raw);
                attempts = (data.attempts || 0) + 1;
            }

            if (attempts >= MAX_FAILED_ATTEMPTS) {
                const lockedUntil = now + LOCKOUT_DURATION_SECONDS;
                localStorage.setItem(key, JSON.stringify({ attempts, lockedUntil }));
                setLockoutTimer(LOCKOUT_DURATION_SECONDS);
                setRemainingAttempts(0);
                setError(`Security Alert: Too many failed login attempts. Access temporarily locked for 5 minutes.`);
            } else {
                localStorage.setItem(key, JSON.stringify({ attempts }));
                const left = MAX_FAILED_ATTEMPTS - attempts;
                setRemainingAttempts(left);
                setError(`Authentication failed. ${left} attempt${left === 1 ? '' : 's'} remaining before temporary lockout.`);
            }
        } catch (e) {
            console.error('Failed to record attempt:', e);
        }
    };

    const clearLockout = () => {
        try {
            localStorage.removeItem(getStorageKey());
            setRemainingAttempts(MAX_FAILED_ATTEMPTS);
            setLockoutTimer(0);
        } catch (e) {
            console.error(e);
        }
    };

    const handleAuth = async (e) => {
        e.preventDefault();
        setError('');
        setSuccessMessage('');

        if (mode === 'login' && lockoutTimer > 0) {
            setError(`Account is locked due to multiple failed attempts. Please wait ${formatTime(lockoutTimer)}.`);
            return;
        }

        setLoading(true);

        try {
            if (mode === 'signup') {
                const { data, error } = await supabase.auth.signUp({
                    email: email.trim(),
                    password: password,
                });

                if (error) {
                    setError(error.message);
                } else if (data.session) {
                    clearLockout();
                    onLogin(data.session);
                } else {
                    setSuccessMessage('Verification link sent! Check your inbox to activate your account.');
                }
            } else if (mode === 'login') {
                const { data, error } = await supabase.auth.signInWithPassword({
                    email: email.trim(),
                    password: password,
                });

                if (error) {
                    recordFailedAttempt();
                } else if (data.session) {
                    clearLockout();
                    onLogin(data.session);
                }
            } else if (mode === 'forgot') {
                const { error } = await supabase.auth.resetPasswordForEmail(email.trim(), {
                    redirectTo: `${window.location.origin}`,
                });

                if (error) {
                    setError(error.message);
                } else {
                    setSuccessMessage('Password recovery link has been dispatched to your email address.');
                }
            }
        } catch (err) {
            setError(err.message || 'An unexpected error occurred.');
        } finally {
            setLoading(false);
        }
    };

    const formatTime = (seconds) => {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}m ${secs < 10 ? '0' : ''}${secs}s`;
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-slate-950 p-4 sm:p-8 relative overflow-hidden font-sans">
            {/* Subtle background glow effect */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-blue-600/10 rounded-full blur-[120px] pointer-events-none"></div>

            <div className="w-full max-w-md bg-slate-900/90 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-[0_0_40px_rgba(0,0,0,0.6)] p-8 sm:p-10 relative z-10">
                
                {/* Header Section */}
                <div className="text-center mb-8">
                    <div className="mx-auto w-12 h-12 bg-blue-600/10 border border-blue-500/20 rounded-xl flex items-center justify-center mb-4 shadow-[0_0_20px_rgba(59,130,246,0.2)]">
                        <Shield className="w-6 h-6 text-blue-400" />
                    </div>
                    <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight font-mono">
                        {mode === 'signup' && 'INITIALIZE ACCESS'}
                        {mode === 'login' && 'SOC ANALYST LOGIN'}
                        {mode === 'forgot' && 'RECOVER CREDENTIALS'}
                    </h2>
                    <p className="text-sm text-slate-400 mt-2 font-mono">
                        {mode === 'signup' && 'Register security operator credentials'}
                        {mode === 'login' && 'Authenticate to access CYPHER operational console'}
                        {mode === 'forgot' && 'Receive secure password reset transmission'}
                    </p>
                </div>

                {/* Session Expired Banner */}
                {sessionExpiredMessage && (
                    <div className="mb-6 text-xs p-3.5 rounded-lg border bg-amber-950/30 border-amber-500/40 text-amber-300 flex items-center gap-2.5 font-mono">
                        <Clock className="w-4 h-4 shrink-0 text-amber-400" />
                        <span>{sessionExpiredMessage}</span>
                    </div>
                )}

                {/* Lockout Warning Banner */}
                {lockoutTimer > 0 && mode === 'login' && (
                    <div className="mb-6 p-4 rounded-lg bg-red-950/40 border border-red-500/50 text-red-300 font-mono text-xs space-y-1">
                        <div className="flex items-center gap-2 font-bold text-red-400">
                            <Lock className="w-4 h-4" />
                            <span>BRUTE-FORCE LOCKOUT ACTIVE</span>
                        </div>
                        <p>Too many failed attempts. Lockout cooldown:</p>
                        <p className="text-lg font-bold text-red-400">{formatTime(lockoutTimer)}</p>
                    </div>
                )}

                {/* Error Messaging */}
                {error && (
                    <div className="mb-6 text-xs p-3.5 rounded-lg border bg-red-900/20 border-red-500/30 text-red-400 flex items-start gap-2.5 font-mono">
                        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                        <span>{error}</span>
                    </div>
                )}

                {/* Success Messaging */}
                {successMessage && (
                    <div className="mb-6 text-xs p-3.5 rounded-lg border bg-emerald-900/20 border-emerald-500/30 text-emerald-400 flex items-start gap-2.5 font-mono">
                        <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
                        <span>{successMessage}</span>
                    </div>
                )}

                <form onSubmit={handleAuth} className="space-y-4">
                    {/* Email Input */}
                    <div className="relative">
                        <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                            <Mail className="h-4 w-4 text-slate-500" />
                        </div>
                        <input
                            type="email"
                            placeholder="Operator Email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            disabled={loading || (mode === 'login' && lockoutTimer > 0)}
                            className="w-full pl-10 pr-4 py-3 bg-slate-950/60 border border-slate-700 rounded-lg text-white text-sm placeholder-slate-500 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none transition-all font-mono disabled:opacity-50"
                            required
                        />
                    </div>

                    {/* Password Input (Hidden in Forgot Password mode) */}
                    {mode !== 'forgot' && (
                        <div>
                            <div className="relative">
                                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                                    <KeyRound className="h-4 w-4 text-slate-500" />
                                </div>
                                <input
                                    type="password"
                                    placeholder="Password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    disabled={loading || (mode === 'login' && lockoutTimer > 0)}
                                    className="w-full pl-10 pr-4 py-3 bg-slate-950/60 border border-slate-700 rounded-lg text-white text-sm placeholder-slate-500 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none transition-all font-mono disabled:opacity-50"
                                    required
                                />
                            </div>

                            {/* Forgot Password link on login mode */}
                            {mode === 'login' && (
                                <div className="flex justify-between items-center mt-2 px-1">
                                    <span className="text-[11px] font-mono text-slate-500">
                                        {remainingAttempts < MAX_FAILED_ATTEMPTS && lockoutTimer === 0 && (
                                            <span className="text-amber-400">{remainingAttempts} attempts left</span>
                                        )}
                                    </span>
                                    <button
                                        type="button"
                                        onClick={() => {
                                            setMode('forgot');
                                            setError('');
                                            setSuccessMessage('');
                                        }}
                                        className="text-xs text-blue-400 hover:text-blue-300 font-mono transition-colors"
                                    >
                                        Forgot Password?
                                    </button>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Submit Button */}
                    <button
                        type="submit"
                        disabled={loading || (mode === 'login' && lockoutTimer > 0)}
                        className="w-full py-3.5 bg-blue-600 text-white font-bold rounded-lg hover:bg-blue-500 hover:shadow-[0_0_20px_rgba(37,99,235,0.4)] disabled:opacity-50 disabled:hover:shadow-none transition-all duration-200 mt-2 flex justify-center items-center gap-2 font-mono tracking-wider text-sm uppercase"
                    >
                        {loading ? (
                            <>
                                <svg className="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                </svg>
                                <span>Verifying...</span>
                            </>
                        ) : (
                            <>
                                {mode === 'signup' && 'Create Account'}
                                {mode === 'login' && 'Authenticate Access'}
                                {mode === 'forgot' && 'Send Reset Link'}
                            </>
                        )}
                    </button>
                </form>

                {/* Bottom Mode Switchers */}
                <div className="mt-6 pt-6 border-t border-slate-800/80 text-center font-mono text-xs">
                    {mode === 'forgot' ? (
                        <button
                            type="button"
                            onClick={() => {
                                setMode('login');
                                setError('');
                                setSuccessMessage('');
                            }}
                            className="inline-flex items-center gap-2 text-slate-400 hover:text-white transition-colors"
                        >
                            <ArrowLeft className="w-3.5 h-3.5" />
                            <span>Return to Sign In</span>
                        </button>
                    ) : (
                        <button
                            type="button"
                            onClick={() => {
                                setMode(mode === 'signup' ? 'login' : 'signup');
                                setError('');
                                setSuccessMessage('');
                            }}
                            className="text-slate-400 hover:text-blue-400 transition-colors"
                        >
                            {mode === 'signup'
                                ? 'Already have credentials? Sign In'
                                : 'Need an account? Request Access'}
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
}
