import { Moon, Sun } from "lucide-react";

function ThemeToggle({ darkMode, setDarkMode }) {
  const toggleTheme = () => {
    setDarkMode((current) => !current);
  };

  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={toggleTheme}
      aria-label={
        darkMode
          ? "Switch to light mode"
          : "Switch to dark mode"
      }
      title={
        darkMode
          ? "Switch to light mode"
          : "Switch to dark mode"
      }
    >
      <span
        className={`theme-icon ${
          !darkMode ? "active" : ""
        }`}
      >
        <Sun size={15} />
      </span>

      <span
        className={`theme-icon ${
          darkMode ? "active" : ""
        }`}
      >
        <Moon size={15} />
      </span>

      <span
        className={`theme-slider ${
          darkMode ? "dark" : "light"
        }`}
      />
    </button>
  );
}

export default ThemeToggle;