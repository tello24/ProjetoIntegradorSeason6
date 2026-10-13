"use client";

import { useSyncExternalStore } from "react";

type ThemePreference = "system" | "light" | "dark";

const storageKey = "wvm-theme";
const themeEvent = "wvm-theme-change";

const options: Array<{ value: ThemePreference; label: string; symbol: string }> = [
  { value: "system", label: "Automático", symbol: "A" },
  { value: "light", label: "Claro", symbol: "☀" },
  { value: "dark", label: "Escuro", symbol: "◐" },
];

function getPreference(): ThemePreference {
  const stored = window.localStorage.getItem(storageKey);
  return stored === "light" || stored === "dark" ? stored : "system";
}

function resolveTheme(preference: ThemePreference) {
  if (preference !== "system") return preference;
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function applyPreference(preference: ThemePreference) {
  document.documentElement.dataset.theme = resolveTheme(preference);
  document.documentElement.style.colorScheme = resolveTheme(preference);
}

function subscribe(callback: () => void) {
  const media = window.matchMedia("(prefers-color-scheme: light)");
  const handlePreferenceChange = () => callback();
  const handleSystemChange = () => {
    if (getPreference() === "system") {
      applyPreference("system");
      callback();
    }
  };
  const handleStorage = (event: StorageEvent) => {
    if (event.key === storageKey) {
      applyPreference(getPreference());
      callback();
    }
  };

  window.addEventListener(themeEvent, handlePreferenceChange);
  window.addEventListener("storage", handleStorage);
  media.addEventListener("change", handleSystemChange);
  return () => {
    window.removeEventListener(themeEvent, handlePreferenceChange);
    window.removeEventListener("storage", handleStorage);
    media.removeEventListener("change", handleSystemChange);
  };
}

export function ThemeToggle({ compact = false }: { compact?: boolean }) {
  const preference = useSyncExternalStore(subscribe, getPreference, () => "system");

  function selectTheme(nextPreference: ThemePreference) {
    if (nextPreference === "system") window.localStorage.removeItem(storageKey);
    else window.localStorage.setItem(storageKey, nextPreference);
    applyPreference(nextPreference);
    window.dispatchEvent(new Event(themeEvent));
  }

  return (
    <div
      aria-label="Escolher aparência"
      className={`theme-toggle${compact ? " theme-toggle--compact" : ""}`}
      role="group"
    >
      {options.map((option) => (
        <button
          aria-label={`Usar tema ${option.label.toLocaleLowerCase("pt-BR")}`}
          aria-pressed={preference === option.value}
          className={preference === option.value ? "theme-toggle__active" : ""}
          key={option.value}
          onClick={() => selectTheme(option.value)}
          title={option.label}
          type="button"
        >
          <span aria-hidden="true">{option.symbol}</span>
          <small>{option.label}</small>
        </button>
      ))}
    </div>
  );
}
