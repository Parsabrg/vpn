// Asks each target an unauthenticated API question. Up means the API itself
// answered: a 401 with its JSON body. Anything else -- a timeout, a TLS or
// DNS failure, a front's own error page -- is down. Nothing about users is
// sent or read.

export async function check(url, fetchImpl = fetch) {
  try {
    const response = await fetchImpl(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(15000),
    });
    const body = await response.text();
    if (response.status === 401 && body.includes('"detail"')) {
      return null;
    }
    return `${url}: HTTP ${response.status}`;
  } catch (error) {
    return `${url}: ${error.name === "TimeoutError" ? "no answer in 15 s" : error.message}`;
  }
}

export function alertMessage(from, to, failures, now = new Date()) {
  return [
    `From: Nebula monitor <${from}>`,
    `To: ${to}`,
    "Subject: Nebula is down",
    `Date: ${now.toUTCString()}`,
    `Message-ID: <${now.getTime()}.${crypto.randomUUID()}@${from.split("@")[1]}>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Checked from Cloudflare just now:",
    "",
    ...failures,
    "",
    "This repeats every 15 minutes until they answer again.",
  ].join("\r\n");
}

async function sendMail(env, raw) {
  const { EmailMessage } = await import("cloudflare:email");
  await env.MAIL.send(new EmailMessage(env.ALERT_FROM, env.ALERT_TO, raw));
}

// ponytail: mails on every failing run (every 15 min) rather than on state
// change; add a KV flag if the repeats get noisy.
export async function run(env, fetchImpl = fetch, send = sendMail) {
  const targets = env.TARGETS.split(",").map((t) => t.trim()).filter(Boolean);
  const failures = (await Promise.all(targets.map((t) => check(t, fetchImpl)))).filter(Boolean);
  if (failures.length > 0 && env.ALERT_TO) {
    await send(env, alertMessage(env.ALERT_FROM, env.ALERT_TO, failures));
  }
  return failures;
}

export default {
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(run(env));
  },
};
