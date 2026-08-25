/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        vault: {
          50: '#f0f1ff',
          100: '#e4e5ff',
          200: '#cfceff',
          300: '#b2abff',
          400: '#9482ff',
          500: '#7c5cff',
          600: '#6e39f7',
          700: '#5f28e3',
          800: '#4f21be',
          900: '#421d9b',
          950: '#270f69',
        },
        dark: {
          bg: '#0f0f23',
          card: '#1a1b2e',
          border: '#2a2b40',
          hover: '#252638',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'slide-in': 'slideIn 0.3s ease-out',
        'fade-in': 'fadeIn 0.2s ease-out',
      },
      keyframes: {
        slideIn: {
          '0%': { transform: 'translateY(-10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
