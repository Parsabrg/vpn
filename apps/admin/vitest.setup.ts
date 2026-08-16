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

// jsdom does not implement HTMLDialogElement.showModal()/close(): tests that
// render ConfirmDialog/StepUpModal need both to toggle `open` and close() to
// fire the native `close` event our components listen for.
if (
  typeof HTMLDialogElement !== "undefined" &&
  typeof HTMLDialogElement.prototype.showModal !== "function"
) {
  HTMLDialogElement.prototype.showModal = function (this: HTMLDialogElement) {
    this.setAttribute("open", "");
  };
  HTMLDialogElement.prototype.close = function (this: HTMLDialogElement) {
    this.removeAttribute("open");
    this.dispatchEvent(new Event("close"));
  };
}
