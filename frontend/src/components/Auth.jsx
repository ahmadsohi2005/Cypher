import { useState } from 'react';
import { supabase } from '../utils/supabaseClient';

export default function Auth({ onLogin }) {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [isSignUp, setIsSignUp] = useState(false);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleAuth = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        const { data, error } = isSignUp
            ? await supabase.auth.signUp({ email, password })
            : await supabase.auth.signInWithPassword({ email, password });

        if (error) {
            setError(error.message);
        } else if (data.session) {
            onLogin(data.session);
        } else if (isSignUp) {
            setError('Check your email for the confirmation link.');
        }
        setLoading(false);
    };

    return (
        <div className="flex justify-center items-center min-h-screen bg-slate-950">
            <form onSubmit={handleAuth} className="p-8 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl w-full max-w-sm">
                <h2 className="text-2xl font-bold text-white mb-6 text-center">
                    {isSignUp ? 'Create Account' : 'SOC Analyst Login'}
                </h2>

                {error && <p className="mb-4 text-sm text-red-400 bg-red-900/20 p-3 rounded border border-red-500/30">{error}</p>}

                <input
                    type="email"
                    placeholder="Email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full p-3 mb-4 bg-slate-950 border border-slate-700 rounded text-white focus:border-blue-500 focus:outline-none"
                    required
                />
                <input
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full p-3 mb-6 bg-slate-950 border border-slate-700 rounded text-white focus:border-blue-500 focus:outline-none"
                    required
                />

                <button type="submit" disabled={loading} className="w-full py-3 bg-blue-600 text-white font-bold rounded hover:bg-blue-500 mb-4 transition-colors">
                    {loading ? 'Processing...' : (isSignUp ? 'Sign Up' : 'Sign In')}
                </button>

                <p className="text-sm text-center text-slate-400 cursor-pointer hover:text-white" onClick={() => setIsSignUp(!isSignUp)}>
                    {isSignUp ? 'Already have an account? Sign In' : 'Need an account? Sign Up'}
                </p>
            </form>
        </div>
    );
}