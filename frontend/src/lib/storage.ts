// Browser storage can throw (private windows, blocked cookies), so every access is guarded.
export function readStorage(store: "local" | "session", key: string): string | null {
  try {
    return (store === "local" ? window.localStorage : window.sessionStorage).getItem(key);
  } catch {
    return null;
  }
}

export function writeStorage(store: "local" | "session", key: string, value: string | null): void {
  try {
    const s = store === "local" ? window.localStorage : window.sessionStorage;
    if (value === null) s.removeItem(key);
    else s.setItem(key, value);
  } catch {
    /* ignore: the app still works, it just won't remember */
  }
}
