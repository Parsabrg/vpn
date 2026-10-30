import { describe, expect, it } from "vitest";

import { parseSetCookie } from "@/lib/api/set-cookie";

describe("parseSetCookie", () => {
  it("reads the CSRF cookie FastAPI issues in production", () => {
    expect(
      parseSetCookie(
        "__Host-nebula_csrf=abc.def; Max-Age=28800; Path=/; SameSite=strict; Secure",
      ),
    ).toEqual({
      name: "__Host-nebula_csrf",
      value: "abc.def",
      maxAge: 28800,
      path: "/",
      sameSite: "strict",
      secure: true,
    });
  });

  it("keeps HttpOnly on the session cookie", () => {
    expect(
      parseSetCookie(
        "__Host-nebula_admin=token; HttpOnly; Path=/; SameSite=Strict; Secure",
      ),
    ).toMatchObject({
      name: "__Host-nebula_admin",
      httpOnly: true,
      sameSite: "strict",
    });
  });

  it("drops Domain, which a __Host- cookie must not carry", () => {
    expect(parseSetCookie("a=b; Domain=example.org; Path=/")).toEqual({
      name: "a",
      value: "b",
      path: "/",
    });
  });

  it("keeps an equals sign inside the value", () => {
    expect(parseSetCookie("a=b=c; Path=/")?.value).toBe("b=c");
  });

  it("unquotes a quoted value", () => {
    expect(parseSetCookie('a="b"')?.value).toBe("b");
  });

  it("reads a clearing cookie's Max-Age of zero and its expiry", () => {
    expect(
      parseSetCookie(
        'nebula_csrf=""; expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; Path=/',
      ),
    ).toMatchObject({ value: "", maxAge: 0, expires: new Date(0) });
  });

  it("returns null for a header with no name", () => {
    expect(parseSetCookie("=value; Path=/")).toBeNull();
    expect(parseSetCookie("no-equals-sign")).toBeNull();
  });
});
