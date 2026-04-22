/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        accent: "#3B82F6",
        "bg-primary": "#1a1f2e",
        "bg-secondary": "#242938",
        "bg-card": "#2d3347",
        "border-color": "#3a4060",
      },
    },
  },
  plugins: [],
}
