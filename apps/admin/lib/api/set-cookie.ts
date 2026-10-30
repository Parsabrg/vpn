/** A Set-Cookie header, in the shape `cookies().set()` takes. */
export interface ParsedSetCookie {
  name: string;
  value: string;
  path?: string;
  maxAge?: number;
  expires?: Date;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: "strict" | "lax" | "none";
}

/**
 * Parses one Set-Cookie header value.
 *
 * Only the attributes FastAPI's admin cookies use. `Domain` is dropped on
 * purpose: the `__Host-` cookies must not carry one, and the others are set
 * for this host anyway. Returns null for anything without a name.
 */
export function parseSetCookie(header: string): ParsedSetCookie | null {
  const [pair = "", ...attributes] = header.split(";");
  const separator = pair.indexOf("=");
  if (separator <= 0) {
    return null;
  }
  const name = pair.slice(0, separator).trim();
  if (!name) {
    return null;
  }
  const cookie: ParsedSetCookie = {
    name,
    value: stripQuotes(pair.slice(separator + 1).trim()),
  };
  for (const attribute of attributes) {
    const [rawKey = "", ...rest] = attribute.split("=");
    const key = rawKey.trim().toLowerCase();
    const value = rest.join("=").trim();
    switch (key) {
      case "path":
        cookie.path = value;
        break;
      case "max-age": {
        const seconds = Number.parseInt(value, 10);
        if (Number.isFinite(seconds)) {
          cookie.maxAge = seconds;
        }
        break;
      }
      case "expires": {
        const date = new Date(value);
        if (!Number.isNaN(date.getTime())) {
          cookie.expires = date;
        }
        break;
      }
      case "secure":
        cookie.secure = true;
        break;
      case "httponly":
        cookie.httpOnly = true;
        break;
      case "samesite": {
        const sameSite = value.toLowerCase();
        if (
          sameSite === "strict" ||
          sameSite === "lax" ||
          sameSite === "none"
        ) {
          cookie.sameSite = sameSite;
        }
        break;
      }
    }
  }
  return cookie;
}

function stripQuotes(value: string): string {
  return value.length >= 2 && value.startsWith('"') && value.endsWith('"')
    ? value.slice(1, -1)
    : value;
}
