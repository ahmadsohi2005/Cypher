import { BouncyArc } from 'ldrs/react';
import 'ldrs/react/BouncyArc.css';

export default function LoadingSpinner({
    text = "Executing...",
    color = "#60a5fa", // Defaulting to Tailwind's blue-400 so it's visible on your dark background
    size = "70",
    speed = "1.65"
}) {
    return (
        <div className="flex flex-col items-center justify-center py-12 gap-4">
            <BouncyArc
                size={size}
                speed={speed}
                color={color}
            />
            {text && (
                <span className="font-medium animate-pulse text-slate-300">
                    {text}
                </span>
            )}
        </div>
    );
}