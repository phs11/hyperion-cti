/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',  // ← ADD THIS LINE HERE
  theme: {
    extend: {
      colors: {
        cti: {
          primary: '#0d9488',  // Hyperion teal
          danger: '#ef4444',   // High threat red
        },
      },
    },
  },
  plugins: [],
}