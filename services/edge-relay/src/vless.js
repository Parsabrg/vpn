// The VLESS request a client opens a stream with, read from its first
// WebSocket message:
//
//   version(1) uuid(16) addonsLength(1) addons command(1) port(2, big-endian)
//   addressType(1) address payload...
//
// Written from the protocol description, not from any other relay's code.

export const TCP = 1;
export const UDP = 2;

/// The 16 bytes of a UUID, or null when it is not one.
export function uuidBytes(text) {
  const hex = String(text).replaceAll('-', '');
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) {
    return null;
  }
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/// The UUIDs the relay admits, from a comma-separated list, or null when
/// the list is empty or any entry is not a UUID. More than one lets the
/// operator rotate: each release is built with a new UUID, and an old one
/// is dropped from the list once the builds that carry it are retired.
export function uuidList(text) {
  const entries = String(text ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '');
  if (entries.length === 0) {
    return null;
  }
  const ids = entries.map(uuidBytes);
  return ids.includes(null) ? null : ids;
}

/// Reads the request header. `ids` is one UUID's bytes or a list of them.
/// Returns `{ error }` for anything that is not a complete header for one of
/// them; the caller closes without saying which.
export function parseRequest(bytes, ids) {
  if (bytes.length < 18) {
    return { error: 'short' };
  }
  // Every byte of every UUID compared, whatever the first mismatch: how
  // long a wrong UUID takes to be refused says nothing about how much of it
  // was right, or which entry it came closest to.
  let matched = 0;
  for (const id of ids instanceof Uint8Array ? [ids] : ids) {
    let different = 0;
    for (let i = 0; i < 16; i++) {
      different |= bytes[1 + i] ^ id[i];
    }
    matched |= different === 0 ? 1 : 0;
  }
  if (matched === 0) {
    return { error: 'user' };
  }
  let at = 18 + bytes[17];
  if (bytes.length < at + 4) {
    return { error: 'short' };
  }
  const command = bytes[at];
  const port = (bytes[at + 1] << 8) | bytes[at + 2];
  const type = bytes[at + 3];
  at += 4;
  let hostname;
  if (type === 1) {
    if (bytes.length < at + 4) {
      return { error: 'short' };
    }
    hostname = Array.from(bytes.subarray(at, at + 4)).join('.');
    at += 4;
  } else if (type === 2) {
    const length = bytes[at];
    if (length === undefined || length === 0 || bytes.length < at + 1 + length) {
      return { error: 'short' };
    }
    hostname = new TextDecoder().decode(bytes.subarray(at + 1, at + 1 + length));
    // A name, not something that could be read as an address with options.
    if (!/^[A-Za-z0-9._-]+$/.test(hostname)) {
      return { error: 'address' };
    }
    at += 1 + length;
  } else if (type === 3) {
    if (bytes.length < at + 16) {
      return { error: 'short' };
    }
    const groups = [];
    for (let i = 0; i < 16; i += 2) {
      groups.push(((bytes[at + i] << 8) | bytes[at + i + 1]).toString(16));
    }
    hostname = `[${groups.join(':')}]`;
    at += 16;
  } else {
    return { error: 'address' };
  }
  if (port === 0 || (command !== TCP && command !== UDP)) {
    return { error: 'command' };
  }
  return { version: bytes[0], command, hostname, port, payload: bytes.subarray(at) };
}
