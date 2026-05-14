/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0E1A1F",
        mist: "#E9F3F5",
        ember: "#FF5D3A",
        pine: "#0A7B62",
        steel: "#2B4550"
      },
      fontFamily: {
        display: ["Sora", "Segoe UI", "sans-serif"],
        body: ["Manrope", "Segoe UI", "sans-serif"]
      }
    }
  },
  plugins: []
};