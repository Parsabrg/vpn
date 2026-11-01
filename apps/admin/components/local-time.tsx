"use client";

import { useEffect, useState } from "react";

/** "2026-11-01 06:57 UTC": the same on the server and in any browser. */
export function formatUtc(date: Date): string {
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** The viewer's own clock, with the zone named so nobody has to guess. */
export function formatLocal(date: Date): string {
  // Spelled out: dateStyle/timeStyle cannot be combined with timeZoneName.
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  }).format(date);
}

/**
 * A moment in time, shown in the viewer's zone.
 *
 * The server and the browser's first (hydrating) render both show UTC,
 * which they agree on; once mounted it switches to the browser's zone.
 * Formatting with the browser's zone during render made the server's text
 * and the browser's differ: React error #418 on every page with a time, and
 * some times left in UTC beside others in local time (2026-11-01 sweep).
 */
export function LocalTime({ value }: { value: string | Date }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    // Deliberate: the one render that must differ from the server's is the
    // one after mounting. useSyncExternalStore kept UTC on a streamed page.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setMounted(true);
  }, []);
  const date = typeof value === "string" ? new Date(value) : value;
  if (Number.isNaN(date.getTime())) {
    return <span>—</span>;
  }
  return (
    <time dateTime={date.toISOString()} title={formatUtc(date)}>
      {mounted ? formatLocal(date) : formatUtc(date)}
    </time>
  );
}
