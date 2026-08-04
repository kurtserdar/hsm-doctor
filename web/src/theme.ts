// Dependency-free theme control: auto (follow the OS), light or dark. The
// choice persists in localStorage; "auto" removes the data-theme attribute so
// the prefers-color-scheme media query drives the palette.
import { ref } from "vue";

export type Theme = "auto" | "light" | "dark";

const STORAGE_KEY = "hsmdoctor_theme";

function detect(): Theme {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved === "light" || saved === "dark" || saved === "auto") return saved;
  return "auto";
}

export const theme = ref<Theme>(detect());

function apply(t: Theme): void {
  const root = document.documentElement;
  if (t === "auto") {
    root.removeAttribute("data-theme");
  } else {
    root.setAttribute("data-theme", t);
  }
}

export function setTheme(t: Theme): void {
  theme.value = t;
  localStorage.setItem(STORAGE_KEY, t);
  apply(t);
}

apply(theme.value);
