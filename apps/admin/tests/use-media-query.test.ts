import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useMediaQuery } from "@/lib/use-media-query";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("useMediaQuery", () => {
  it("reflects the initial matches value", () => {
    vi.stubGlobal("matchMedia", (query: string): MediaQueryList => ({
      matches: true,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }));

    const { result } = renderHook(() => useMediaQuery("(max-width: 48rem)"));
    expect(result.current).toBe(true);
  });

  it("updates when the media query's change event fires -- the same mechanism drives both responsive breakpoints and prefers-reduced-motion", () => {
    let matches = false;
    let listener: (() => void) | undefined;
    vi.stubGlobal("matchMedia", (query: string) => ({
      get matches() {
        return matches;
      },
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: (_event: string, callback: () => void) => {
        listener = callback;
      },
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }));

    const { result } = renderHook(() =>
      useMediaQuery("(prefers-reduced-motion: reduce)"),
    );
    expect(result.current).toBe(false);

    matches = true;
    act(() => {
      listener?.();
    });
    expect(result.current).toBe(true);
  });
});
