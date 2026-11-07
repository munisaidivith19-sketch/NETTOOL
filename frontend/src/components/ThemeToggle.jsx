import { useEffect, useState } from "react";

const STORAGE_KEY = "netmap.theme";

// localStorage holds only this display preference, never tokens or user data.
// Every access is wrapped because storage can be blocked (private windows, strict settings).
function readSaved() {
  try {
    const value = window.localStorage.getItem(STORAGE_KEY);
    return value === "light" || value === "dark" ? value : null;
  } catch {
    return null;
  }
}

function systemTheme() {
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export default function ThemeToggle() {
  // null = no choice made, so the CSS follows the operating system setting.
  const [saved, setSaved] = useState(readSaved);
  const theme = saved ?? systemTheme();

  useEffect(() => {
    if (saved) document.documentElement.dataset.theme = saved;
  }, [saved]);

  function toggle() {
    const next = theme === "dark" ? "light" : "dark";
    setSaved(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Not saved; the choice still applies for this visit.
    }
  }

  const next = theme === "dark" ? "light" : "dark";
  return (
    <button type="button" className="theme-toggle" onClick={toggle} aria-label={`Switch to ${next} theme`}>
      <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
        <circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" strokeWidth="1.5" />
        <path d="M8 1.5a6.5 6.5 0 0 1 0 13z" fill="currentColor" />
      </svg>
      {theme === "dark" ? "Dark" : "Light"}
    </button>
  );
}
