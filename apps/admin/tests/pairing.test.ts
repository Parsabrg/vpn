import { describe, expect, it } from "vitest";
import { toDevicePairing } from "@/lib/pairing";

describe("the pairing view", () => {
  it("carries the QR code as an image, never as markup", () => {
    const pairing = toDevicePairing({
      link: "https://203.0.113.7/pair#v=1&d=x",
      app_link: "nebula://pair?u=https%3A%2F%2F203.0.113.7&d=x",
      qr_svg: '<svg xmlns="http://www.w3.org/2000/svg"></svg>',
      deployment_id: "x",
      ca_sha256: null,
    });

    expect(pairing.qrImage.startsWith("data:image/svg+xml;base64,")).toBe(true);
    expect(
      Buffer.from(pairing.qrImage.split(",")[1] ?? "", "base64").toString(
        "utf8",
      ),
    ).toContain("<svg");
    expect(pairing.link).toBe("https://203.0.113.7/pair#v=1&d=x");
  });
});
