import { supabase } from './supabaseClient';

export const getHistory = async (userId) => {
    if (!userId) return [];

    const { data, error } = await supabase
        .from('user_history')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(50);

    if (error) {
        console.error("Error fetching history:", error);
        return [];
    }

    // Force it to return an array even if Supabase returns null
    return data || [];
};

export const saveActivity = async (activityData) => {
    console.log("1. saveActivity triggered with:", activityData);

    if (!activityData) return;
    const { module, action, target, summary } = activityData;

    // Check if the app knows who is logged in
    const { data: { session }, error: sessionError } = await supabase.auth.getSession();
    console.log("2. Session status:", session ? "Logged in" : "Missing", sessionError || "");

    if (!session?.user?.id) {
        console.error("3. ABORT: No user session found. Cannot save data.");
        return;
    }

    console.log("4. Sending data to Supabase...");

    // Attempt the save and force Supabase to tell us what went wrong
    const { data, error } = await supabase
        .from('user_history')
        .insert([{
            user_id: session.user.id,
            module,
            action,
            target,
            summary
        }])
        .select();

    if (error) {
        console.error("5. SUPABASE ERROR:", error.message, error.details);
    } else {
        console.log("6. SUCCESS! Data saved:", data);
    }
};

export const clearHistory = async (userId) => {
    if (!userId) return;

    const { error } = await supabase
        .from('user_history')
        .delete()
        .eq('user_id', userId);

    if (error) {
        console.error("Error clearing history:", error);
    }
};