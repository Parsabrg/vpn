import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// apiFetch JSON-encodes `body` itself. Encoded twice, the API received a
// string and refused it (422): renaming a server, changing its state, a
// quota and a DNS profile all failed with "Something went wrong" (2026-10-30).
describe("API request bodies", () => {
  it("are passed to apiFetch as objects, never pre-encoded", () => {
    const dir = join(__dirname, "..", "lib");
    const offenders = readdirSync(dir)
      .filter((name) => name.endsWith(".ts"))
      .filter((name) =>
        /body:\s*JSON\.stringify\(/.test(readFileSync(join(dir, name), "utf8")),
      );
    expect(offenders).toEqual([]);
  });
});
