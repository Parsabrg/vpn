import Link from "next/link";
import type { AdminSession } from "@/lib/auth/types";
import { LogoutButton } from "./logout-button";

const navigation = [
  { href: "/", label: "Overview" },
  { href: "/requests", label: "Requests" },
  { href: "/users", label: "Users" },
  { href: "/audit-log", label: "Audit log" },
  { href: "/email-deliveries", label: "Email" },
  { href: "/permissions", label: "Permissions" },
  { href: "/assignments", label: "Assignments" },
  { href: "/server-health", label: "Server health" },
] as const;

export function AdminHeader({ session }: { session: AdminSession }) {
  return (
    <header className="site-header">
      <div className="site-header__inner">
        <Link
          className="brand"
          href="/"
          aria-label="Nebula administration overview"
        >
          <span className="brand__mark" aria-hidden="true">
            N
          </span>
          <span>
            <strong>Nebula</strong>
            <small>Administration</small>
          </span>
        </Link>
        <nav aria-label="Primary navigation">
          <ul className="nav-list">
            {navigation.map((item) => (
              <li key={item.href}>
                <Link href={item.href}>{item.label}</Link>
              </li>
            ))}
          </ul>
        </nav>
        <div className="admin-header__account">
          <span className="badge badge--role" aria-label="Signed in role">
            {session.role}
          </span>
          <LogoutButton />
        </div>
      </div>
    </header>
  );
}
