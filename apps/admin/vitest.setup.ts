import "@testing-library/jest-dom/vitest";

// jsdom does not implement matchMedia. Tests that exercise useMediaQuery
// (responsive layout, prefers-reduced-motion) override this per-test with
// vi.stubGlobal("matchMedia", ...); this default keeps every other test
// from crashing on an undefined window.matchMedia.
if (typeof window !== "undefined" && typeof window.matchMedia !== "function") {
  window.matchMedia = (query: string): MediaQueryList => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  });
}
