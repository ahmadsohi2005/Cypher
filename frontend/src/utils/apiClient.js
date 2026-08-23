import axios from 'axios';
import { supabase } from './supabaseClient';

// Resolve API base URL dynamically for local dev, Vercel, and Render
const getBaseUrl = () => {
    const envUrl = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL;
    if (envUrl) {
        return envUrl.endsWith('/') ? envUrl.slice(0, -1) : envUrl;
    }
    return 'http://127.0.0.1:8000';
};

export const API_ROOT = getBaseUrl();

const apiClient = axios.create({
    baseURL: API_ROOT,
    timeout: 30000,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Automatically attach Supabase JWT Bearer token to all outgoing requests
apiClient.interceptors.request.use(
    async (config) => {
        try {
            const { data: { session } } = await supabase.auth.getSession();
            if (session?.access_token) {
                config.headers.Authorization = `Bearer ${session.access_token}`;
            }
        } catch (error) {
            console.error('Failed to attach auth token to request:', error);
        }
        return config;
    },
    (error) => Promise.reject(error)
);

// Response interceptor for handling auth errors
apiClient.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            console.warn('API returned 401 Unauthorized. Session might be invalid or expired.');
        } else if (error.response?.status === 429) {
            console.warn('API returned 429 Rate Limit Exceeded.');
        }
        return Promise.reject(error);
    }
);

export default apiClient;
