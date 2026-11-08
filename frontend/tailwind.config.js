/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50: "#e0f8ff",
          100: "#b5efff",
          200: "#7fe5ff",
          300: "#38d9ff",
          400: "#20d5ee",
          500: "#087f9e",
          600: "#0d7992",
          700: "#0b5f75",
          800: "#0a4b5c",
          900: "#073a48",
          950: "#04222c",
        },
        severity: {
          critical: {
            bg: "#fee2e2",
            text: "#991b1b",
            border: "#fca5a5",
            darkBg: "rgba(153, 27, 27, 0.2)",
            darkText: "#fca5a5",
            darkBorder: "#991b1b",
          },
          high: {
            bg: "#ffedd5",
            text: "#9a3412",
            border: "#fdba74",
            darkBg: "rgba(154, 52, 18, 0.2)",
            darkText: "#fdba74",
            darkBorder: "#9a3412",
          },
          medium: {
            bg: "#fef9c3",
            text: "#854d0e",
            border: "#fde047",
            darkBg: "rgba(133, 77, 14, 0.2)",
            darkText: "#fde047",
            darkBorder: "#854d0e",
          },
          low: {
            bg: "#dcfce7",
            text: "#166534",
            border: "#86efac",
            darkBg: "rgba(22, 101, 52, 0.2)",
            darkText: "#86efac",
            darkBorder: "#166534",
          },
          info: {
            bg: "#e0f2fe",
            text: "#0369a1",
            border: "#7dd3fc",
            darkBg: "rgba(3, 105, 161, 0.2)",
            darkText: "#7dd3fc",
            darkBorder: "#0369a1",
          },
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
    },
  },
  plugins: [],
};
