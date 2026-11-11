import { useCallback, useEffect, useState } from "react";
import { readStorage, writeStorage } from "./lib/storage";

export type Theme = "dark" | "light";
const KEY = "securlyq.theme";

function initial(): Theme {
  const saved = readStorage("local", KEY);
  return saved === "light" || saved === "dark" ? saved : "dark"; // dark is the default
}

export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(initial);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    writeStorage("local", KEY, theme);
  }, [theme]);
  const toggle = useCallback(() => setTheme((t) => (t === "dark" ? "light" : "dark")), []);
  return [theme, toggle];
}
