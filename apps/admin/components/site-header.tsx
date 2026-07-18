import Link from "next/link";

const navigation = [
  { href: "/", label: "Overview" },
  { href: "/health", label: "Health" },
  { href: "/about", label: "About" },
] as const;

export function SiteHeader() {
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
      </div>
    </header>
  );
}
