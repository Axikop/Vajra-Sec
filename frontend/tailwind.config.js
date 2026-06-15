/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg:      "#0b0d10",
        surface: "#12161c",
        elev:    "#171c24",
        border:  "#252b35",
        text:    "#e6e8eb",
        muted:   "#8b95a3",
        accent:  "#3b82f6",
        success: "#10b981",
        warn:    "#f59e0b",
        danger:  "#ef4444",
        critical:"#dc2626",
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "monospace"],
      },
      boxShadow: {
        soft: "0 1px 2px 0 rgba(0,0,0,0.4), 0 1px 3px 0 rgba(0,0,0,0.3)",
      },
    },
  },
  plugins: [],
};
