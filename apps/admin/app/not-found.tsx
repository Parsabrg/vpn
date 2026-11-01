import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Not found",
};

/**
 * A wrong address in the panel. Next's own page was black with no way back
 * (found in the 2026-11-01 sweep).
 */
export default function NotFound() {
  return (
    <main id="main-content" className="page-shell" tabIndex={-1}>
      <section className="page-heading" aria-labelledby="not-found-title">
        <h1 id="not-found-title">Page not found</h1>
        <p>There is no page at this address in the administration panel.</p>
        <p>
          <Link className="button button--primary" href="/">
            Go to the overview
          </Link>
        </p>
      </section>
    </main>
  );
}
