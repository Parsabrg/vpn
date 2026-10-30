import assert from "node:assert/strict";
import { test } from "node:test";
import { alertMessage, run } from "../src/index.js";

const env = {
  TARGETS: "https://up/, https://front-error/,https://gone/",
  ALERT_FROM: "monitor@example.org",
  ALERT_TO: "owner@example.com",
};
const answers = {
  "https://up/": () => new Response('{"detail":"Authentication was not accepted"}', { status: 401 }),
  "https://front-error/": () => new Response("<html>404</html>", { status: 404 }),
  "https://gone/": () => { throw new TypeError("connection refused"); },
};
const fake = async (url) => answers[url]();

test("mails once, naming only the targets that fail", async () => {
  const sent = [];
  const failures = await run(env, fake, async (_env, raw) => sent.push(raw));
  assert.deepEqual(failures, ["https://front-error/: HTTP 404", "https://gone/: connection refused"]);
  assert.equal(sent.length, 1);
  assert.match(sent[0], /HTTP 404\r\nhttps:\/\/gone\/: connection refused/);
  assert.doesNotMatch(sent[0], /https:\/\/up\//);
});

test("stays quiet when everything is up", async () => {
  let sent = false;
  assert.deepEqual(await run({ ...env, TARGETS: "https://up/" }, fake, async () => { sent = true; }), []);
  assert.equal(sent, false);
});

test("the message has the headers Email Routing requires", () => {
  const raw = alertMessage("monitor@example.org", "owner@example.com", ["x: HTTP 502"], new Date(0));
  for (const header of ["From: Nebula monitor <monitor@example.org>", "To: owner@example.com", "Subject: Nebula is down", "Message-ID: <0.", "Date: Thu, 01 Jan 1970"]) {
    assert.ok(raw.includes(header), header);
  }
});
