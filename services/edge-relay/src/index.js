// Nebula's free relay: VLESS over WebSocket on a Cloudflare Worker.
//
// For people with no Nebula server. It keeps nothing and knows nobody: one
// shared UUID admits every copy of the app, no request is logged, and there
// is no account behind it. UUID may list several, comma-separated, so a
// release can carry a new one while older builds keep working.
//
// What a Worker cannot do, and so this cannot either:
//  - UDP. Only DNS is carried, as DNS over TCP to the same resolver.
//  - Connect to a site that is itself on Cloudflare. Those go through
//    RELAY when one is set, and fail when it is not.
//  - More than the plan's requests: each stream a client opens is one.

import { connect } from 'cloudflare:sockets';

import { parseRequest, TCP, uuidList } from './vless.js';

export default {
  async fetch(request, env) {
    const id = uuidList(env.UUID);
    if (id === null) {
      return new Response('UUID is not set or not a UUID list\n', { status: 503 });
    }
    if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      // Nothing to see for a browser, a scanner or a health check.
      return new Response(null, { status: 404 });
    }
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();
    // Bytes, whatever the runtime's default for binary messages is: a Blob
    // would read as an empty header.
    server.binaryType = 'arraybuffer';
    relay(server, id, parseRelay(env.RELAY));
    return new Response(null, { status: 101, webSocket: client });
  },
};

/// `host` or `host:port`, where a stream that got no answer is tried again.
/// Null when unset or unreadable.
export function parseRelay(text) {
  const match = /^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::(\d{1,5}))?$/.exec(
    String(text ?? '').trim(),
  );
  if (match === null) {
    return null;
  }
  return { hostname: match[1], port: match[2] ? Number(match[2]) : null };
}

function relay(ws, id, fallback) {
  let writer = null;
  // One message at a time, in the order they came: the first opens the
  // stream, and nothing may overtake it.
  let queue = Promise.resolve();
  const end = () => {
    try {
      ws.close(1000);
    } catch {
      // Already closed.
    }
  };

  // Connects, makes that the destination of the messages that follow, and
  // sends what the client put after its header. A refused connection shows
  // as a write that fails or a stream that ends empty; the pump reports
  // either as no answer.
  async function dial(target, payload) {
    const socket = connect(target);
    writer = socket.writable.getWriter();
    if (payload.length > 0) {
      await writer.write(payload).catch(() => {});
    }
    return socket.readable;
  }

  async function serve(request, readable) {
    const head = new Uint8Array([request.version, 0]);
    if (await pump(readable, ws, head)) {
      return;
    }
    // Nothing came back at all: Cloudflare's own addresses refuse a Worker.
    // Once more through the relay, with what the client had sent so far.
    if (fallback !== null && request.command === TCP) {
      const target = { hostname: fallback.hostname, port: fallback.port ?? request.port };
      await pump(await dial(target, request.payload), ws, head);
    }
  }

  async function open(first) {
    const request = parseRequest(first, id);
    if (request.error) {
      throw new Error(request.error);
    }
    // UDP is DNS or nothing. A VLESS UDP stream frames each packet with a
    // two-byte length, which is exactly how DNS over TCP frames a message:
    // the bytes go to the resolver's TCP port as they are.
    if (request.command !== TCP && request.port !== 53) {
      throw new Error('udp');
    }
    const target = { hostname: request.hostname, port: request.port };
    const readable = await dial(target, request.payload);
    // Not awaited: it runs for the life of the stream, while later messages
    // keep arriving through the queue.
    serve(request, readable).finally(end);
  }

  ws.addEventListener('message', (event) => {
    const chunk =
      typeof event.data === 'string'
        ? new TextEncoder().encode(event.data)
        : new Uint8Array(event.data);
    queue = queue.then(() => (writer ? writer.write(chunk) : open(chunk))).catch(end);
  });
  const closed = () => {
    queue = queue.then(() => writer?.close()).catch(() => {});
  };
  ws.addEventListener('close', closed);
  ws.addEventListener('error', closed);
}

/// Copies a stream to the WebSocket, the response header ahead of the first
/// bytes. True when anything arrived.
async function pump(readable, ws, head) {
  let answered = false;
  try {
    const reader = readable.getReader();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) {
        break;
      }
      if (answered) {
        ws.send(value);
        continue;
      }
      answered = true;
      const framed = new Uint8Array(head.length + value.length);
      framed.set(head);
      framed.set(value, head.length);
      ws.send(framed);
    }
  } catch {
    // The far side refused or reset: the same as an ended stream.
  }
  return answered;
}
