import assert from 'node:assert/strict';
import { test } from 'node:test';

import { parseRequest, TCP, UDP, uuidBytes, uuidList } from '../src/vless.js';

const UUID = '0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b';
const id = uuidBytes(UUID);

function header({ user = id, addons = [], command = TCP, port = 443, address, payload = [] }) {
  return new Uint8Array([
    0,
    ...user,
    addons.length,
    ...addons,
    command,
    port >> 8,
    port & 0xff,
    ...address,
    ...payload,
  ]);
}

const name = (text) => [2, text.length, ...new TextEncoder().encode(text)];

test('a UUID is sixteen bytes, or it is not one', () => {
  assert.equal(id.length, 16);
  assert.equal(id[0], 0x0f);
  assert.equal(id[15], 0x0b);
  assert.equal(uuidBytes('not-a-uuid'), null);
  assert.equal(uuidBytes(''), null);
  assert.equal(uuidBytes(undefined), null);
});

test('a name, a port and what follows the header', () => {
  const request = parseRequest(
    header({ address: name('example.com'), payload: [1, 2, 3] }),
    id,
  );
  assert.equal(request.error, undefined);
  assert.equal(request.command, TCP);
  assert.equal(request.hostname, 'example.com');
  assert.equal(request.port, 443);
  assert.deepEqual(Array.from(request.payload), [1, 2, 3]);
});

test('addresses, with addons in the way', () => {
  const v4 = parseRequest(
    header({ addons: [9, 9, 9], command: UDP, port: 53, address: [1, 94, 140, 14, 140] }),
    id,
  );
  assert.equal(v4.hostname, '94.140.14.140');
  assert.equal(v4.port, 53);
  assert.equal(v4.command, UDP);
  assert.equal(v4.payload.length, 0);

  const v6 = parseRequest(
    header({ address: [3, 0x26, 0x06, 0x47, 0, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11] }),
    id,
  );
  assert.equal(v6.hostname, '[2606:4700:4700:0:0:0:0:1111]');
});

test('anyone else, and anything malformed, is refused', () => {
  const other = uuidBytes('11111111-1111-4111-8111-111111111111');
  const good = header({ address: name('example.com') });
  assert.equal(parseRequest(header({ user: other, address: name('example.com') }), id).error, 'user');
  // Cut anywhere, it is short rather than read past its end.
  for (let length = 0; length < good.length; length++) {
    assert.ok(parseRequest(good.subarray(0, length), id).error, `cut at ${length}`);
  }
  assert.equal(parseRequest(header({ address: [9, 1, 2, 3, 4] }), id).error, 'address');
  assert.equal(parseRequest(header({ address: name('a b') }), id).error, 'address');
  assert.equal(parseRequest(header({ address: name('example.com'), port: 0 }), id).error, 'command');
  assert.equal(parseRequest(header({ address: name('example.com'), command: 3 }), id).error, 'command');
});

test('a list of UUIDs admits each of them and nobody else', () => {
  const second = '22222222-2222-4222-8222-222222222222';
  const ids = uuidList(` ${UUID} ,${second},`);
  assert.equal(ids.length, 2);
  for (const user of [id, uuidBytes(second)]) {
    const request = parseRequest(header({ user, address: name('example.com') }), ids);
    assert.equal(request.error, undefined);
  }
  const other = uuidBytes('11111111-1111-4111-8111-111111111111');
  assert.equal(parseRequest(header({ user: other, address: name('example.com') }), ids).error, 'user');
});

test('a UUID list with nothing in it, or anything that is not a UUID, is unset', () => {
  assert.equal(uuidList(undefined), null);
  assert.equal(uuidList(''), null);
  assert.equal(uuidList(' , '), null);
  assert.equal(uuidList(`${UUID},not-a-uuid`), null);
});
