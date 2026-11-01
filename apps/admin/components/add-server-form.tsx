"use client";

import { type FormEvent, useState } from "react";
import { type JoinToken, mintJoinToken } from "@/lib/node-actions";
import { endedSession } from "@/lib/end-session";
import { LocalTime } from "@/components/local-time";

/**
 * Adding a server: name it, then paste one command on it. Before this it
 * took a CLI command on this server and a hand install on the new one.
 */
export function AddServerForm() {
  const [joined, setJoined] = useState<JoinToken | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [copied, setCopied] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    const label = String(new FormData(event.currentTarget).get("label") ?? "")
      .trim()
      .toLowerCase()
      // "Amsterdam 1" means amsterdam-1; the browser refusing it did not help.
      .replace(/[^a-z0-9-]+/g, "-")
      .replace(/^-+|-+$/g, "");
    const result = await mintJoinToken(label);
    setPending(false);
    if (!result.ok) {
      if (endedSession(result)) {
        return;
      }
      setError(result.message);
      return;
    }
    setJoined(result.data);
  }

  if (joined) {
    const command = `sudo ./install.sh --join ${joined.apiUrl} --token ${joined.token}`;
    return (
      <div>
        <p role="status">
          On the new server (Ubuntu or Debian), clone Nebula, then run this in
          its folder. It works once, until{" "}
          {<LocalTime value={joined.expiresAt} />}.
        </p>
        <pre className="command" aria-label="Command for the new server">
          {command}
        </pre>
        <button
          type="button"
          className="button button--primary"
          onClick={async () => {
            await navigator.clipboard.writeText(command);
            setCopied(true);
          }}
        >
          {copied ? "Copied" : "Copy command"}
        </button>
        <p className="section-note">
          It asks for the new server&apos;s domain name, installs the VPN
          engines and joins as <strong>{joined.label}</strong>, with its
          protocols enabled. Then assign it to users from their pages.
        </p>
      </div>
    );
  }

  return (
    <form className="auth-form" onSubmit={submit}>
      <div className="field">
        <label htmlFor="label" className="field__label">
          Name for the new server
        </label>
        <input
          id="label"
          name="label"
          required
          maxLength={64}
          placeholder="e.g. amsterdam-1"
        />
        <p className="section-note">
          Becomes lowercase letters, digits and dashes.
        </p>
      </div>
      {error ? <p role="alert">{error}</p> : null}
      <button
        type="submit"
        className="button button--primary"
        disabled={pending}
      >
        {pending ? "Creating…" : "Create join command"}
      </button>
    </form>
  );
}
