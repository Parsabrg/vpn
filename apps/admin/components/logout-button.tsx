"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { readCsrfCookie } from "@/lib/csrf-client";

export function LogoutButton() {
  const router = useRouter();
  const [pending, setPending] = useState(false);

  async function handleLogout() {
    setPending(true);
    const csrfToken = readCsrfCookie();
    const headers: HeadersInit = {};
    if (csrfToken) {
      headers["X-CSRF-Token"] = csrfToken;
    }
    try {
      await fetch("/api/admin/auth/logout", {
        method: "POST",
        headers,
        body: "{}",
      });
    } finally {
      router.push("/login");
      router.refresh();
    }
  }

  return (
    <button
      type="button"
      className="button button--ghost"
      disabled={pending}
      onClick={() => {
        void handleLogout();
      }}
    >
      {pending ? "Signing out…" : "Sign out"}
    </button>
  );
}
