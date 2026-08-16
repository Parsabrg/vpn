"use client";

import { useSyncExternalStore } from "react";

function hasMatchMedia(): boolean {
  return (
    typeof window !== "undefined" && typeof window.matchMedia === "function"
  );
}

function subscribe(query: string) {
  return (onChange: () => void) => {
    if (!hasMatchMedia()) {
      return () => {};
    }
    const media = window.matchMedia(query);
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  };
}

function getSnapshot(query: string): boolean {
  return hasMatchMedia() ? window.matchMedia(query).matches : false;
}

function getServerSnapshot(): boolean {
  return false;
}

/**
 * Wraps `window.matchMedia` so responsive and reduced-motion behavior is
 * driven by JS state rather than pure CSS: jsdom does not evaluate media
 * queries, so a CSS-only responsive layout would be real in the browser but
 * untestable here. `vitest.setup.ts` stubs `window.matchMedia` for tests.
 * `useSyncExternalStore` is the React-recommended way to subscribe to a
 * browser API like this without the cascading-render issue plain
 * `useEffect(() => setState(...))` has.
 */
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    subscribe(query),
    () => getSnapshot(query),
    getServerSnapshot,
  );
}
