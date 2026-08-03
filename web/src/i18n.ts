// Minimal, dependency-free internationalization: a reactive locale plus a
// t(key, params) lookup over the English/Turkish dictionaries. Only UI chrome
// is translated — text that comes from the API (finding titles, remediation,
// verdicts) stays in the language the server produced it in.
import { ref } from "vue";
import { messages } from "./locales";

export type Locale = "en" | "tr";

const STORAGE_KEY = "hsmdoctor_locale";

function detect(): Locale {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved === "en" || saved === "tr") return saved;
  return navigator.language?.toLowerCase().startsWith("tr") ? "tr" : "en";
}

export const locale = ref<Locale>(detect());

export function setLocale(l: Locale): void {
  locale.value = l;
  localStorage.setItem(STORAGE_KEY, l);
  document.documentElement.setAttribute("lang", l);
}

// t looks up a key in the active locale, falling back to English then the key
// itself, and substitutes {name} placeholders from params.
export function t(key: string, params?: Record<string, string | number>): string {
  const active = messages[locale.value] ?? messages.en;
  let s = active[key] ?? messages.en[key] ?? key;
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      s = s.replace(new RegExp(`\\{${k}\\}`, "g"), String(v));
    }
  }
  return s;
}

// Initialize the document language on load.
document.documentElement.setAttribute("lang", locale.value);
