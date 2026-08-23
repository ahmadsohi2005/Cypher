import { useState } from 'react';
import { supabase } from '../utils/supabaseClient';
import { Lock, Eye, EyeOff, CheckCircle2, AlertTriangle, ShieldCheck } from 'lucide-react';

export default function ResetPasswordModal({ isOpen, onClose, onSuccess }) {
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [successMessage, setSuccessMessage] = useState('');

    if (!isOpen) return null;

    // Check basic password strength
    const hasMinLength = newPassword.length >= 8;
    const hasNumber = /\d/.test(newPassword);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(newPassword);
    const passwordsMatch = newPassword && newPassword === confirmPassword;

    const handleUpdatePassword = async (e) => {
        e.preventDefault();
        setError('');
        setSuccessMessage('');

        if (!hasMinLength) {
            setError('Password must be at least 8 characters long.');
            return;
        }

        if (!passwordsMatch) {
            setError('Passwords do not match.');
            return;
        }

        setLoading(true);

        try {
            const { data, error } = await supabase.auth.updateUser({
                password: newPassword,
            });

            if (error) {
                setError(error.message);
            } else {
                setSuccessMessage('Password updated successfully! Your credentials are now secured.');
                setTimeout(() => {
                    if (onSuccess) onSuccess();
                    if (onClose) onClose();
                }, 2000);
            }
        } catch (err) {
            setError(err.message || 'An unexpected error occurred.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
            <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-[0_0_50px_rgba(0,0,0,0.8)] p-6 sm:p-8 relative">
                
                {/* Header */}
                <div className="text-center mb-6">
                    <div className="mx-auto w-12 h-12 bg-blue-600/10 border border-blue-500/20 rounded-xl flex items-center justify-center mb-3">
                        <Lock className="w-6 h-6 text-blue-400" />
                    </div>
                    <h3 className="text-2xl font-bold text-white tracking-wide">Set New Password</h3>
                    <p className="text-xs text-slate-400 mt-1 font-mono">
                        Password recovery authorized. Enter your new security credentials.
                    </p>
                </div>

                {/* Status Messages */}
                {error && (
                    <div className="mb-4 p-3 rounded-lg bg-red-900/20 border border-red-500/30 text-red-400 text-xs flex items-center gap-2 font-mono">
                        <AlertTriangle className="w-4 h-4 shrink-0" />
                        <span>{error}</span>
                    </div>
                )}

                {successMessage && (
                    <div className="mb-4 p-3 rounded-lg bg-emerald-900/20 border border-emerald-500/30 text-emerald-400 text-xs flex items-center gap-2 font-mono">
                        <CheckCircle2 className="w-4 h-4 shrink-0" />
                        <span>{successMessage}</span>
                    </div>
                )}

                {/* Form */}
                <form onSubmit={handleUpdatePassword} className="space-y-4">
                    <div>
                        <label className="block text-xs font-mono text-slate-400 mb-1 uppercase tracking-wider">
                            New Password
                        </label>
                        <div className="relative">
                            <input
                                type={showPassword ? 'text' : 'password'}
                                value={newPassword}
                                onChange={(e) => setNewPassword(e.target.value)}
                                placeholder="Enter at least 8 characters"
                                required
                                className="w-full pl-3 pr-10 py-2.5 bg-slate-950/60 border border-slate-700 rounded-lg text-white text-sm placeholder-slate-500 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none transition-all font-mono"
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500 hover:text-slate-300"
                            >
                                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                        </div>
                    </div>

                    <div>
                        <label className="block text-xs font-mono text-slate-400 mb-1 uppercase tracking-wider">
                            Confirm Password
                        </label>
                        <input
                            type={showPassword ? 'text' : 'password'}
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            placeholder="Re-type new password"
                            required
                            className="w-full px-3 py-2.5 bg-slate-950/60 border border-slate-700 rounded-lg text-white text-sm placeholder-slate-500 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none transition-all font-mono"
                        />
                    </div>

                    {/* Requirements Checklist */}
                    <div className="p-3 bg-slate-950/40 rounded border border-slate-800 space-y-1.5 text-[11px] font-mono text-slate-400">
                        <div className={`flex items-center gap-2 ${hasMinLength ? 'text-emerald-400' : 'text-slate-500'}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${hasMinLength ? 'bg-emerald-400' : 'bg-slate-600'}`}></span>
                            Minimum 8 characters
                        </div>
                        <div className={`flex items-center gap-2 ${hasNumber ? 'text-emerald-400' : 'text-slate-500'}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${hasNumber ? 'bg-emerald-400' : 'bg-slate-600'}`}></span>
                            Contains at least one number
                        </div>
                        <div className={`flex items-center gap-2 ${hasSpecial ? 'text-emerald-400' : 'text-slate-500'}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${hasSpecial ? 'bg-emerald-400' : 'bg-slate-600'}`}></span>
                            Contains special character (!@#$...)
                        </div>
                        <div className={`flex items-center gap-2 ${passwordsMatch && newPassword ? 'text-emerald-400' : 'text-slate-500'}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${passwordsMatch && newPassword ? 'bg-emerald-400' : 'bg-slate-600'}`}></span>
                            Passwords match
                        </div>
                    </div>

                    <button
                        type="submit"
                        disabled={loading || !hasMinLength || !passwordsMatch}
                        className="w-full py-3 bg-blue-600 text-white font-bold rounded-lg hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all text-sm font-mono tracking-wider flex items-center justify-center gap-2"
                    >
                        {loading ? 'SECURING CREDENTIALS...' : 'CONFIRM & SAVE PASSWORD'}
                    </button>
                </form>
            </div>
        </div>
    );
}
