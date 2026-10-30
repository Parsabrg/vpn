import Link from "next/link";

interface PaginationControlsProps {
  total: number;
  limit: number;
  offset: number;
  basePath: string;
  searchParams: Record<string, string | undefined>;
}

function buildHref(
  basePath: string,
  searchParams: Record<string, string | undefined>,
  offset: number,
): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(searchParams)) {
    if (value) {
      params.set(key, value);
    }
  }
  params.set("offset", String(offset));
  return `${basePath}?${params.toString()}`;
}

export function PaginationControls({
  total,
  limit,
  offset,
  basePath,
  searchParams,
}: PaginationControlsProps) {
  const hasPrev = offset > 0;
  const hasNext = offset + limit < total;
  const prevOffset = Math.max(0, offset - limit);
  const nextOffset = offset + limit;
  const start = total === 0 ? 0 : offset + 1;
  const end = Math.min(offset + limit, total);

  return (
    <nav className="pagination" aria-label="Pagination">
      <p>{total === 0 ? "0 results" : `${start}–${end} of ${total}`}</p>
      <div className="pagination__controls">
        {hasPrev ? (
          <Link
            className="button button--secondary"
            href={buildHref(basePath, searchParams, prevOffset)}
          >
            Previous
          </Link>
        ) : (
          <span className="button button--secondary" aria-disabled="true">
            Previous
          </span>
        )}
        {hasNext ? (
          <Link
            className="button button--secondary"
            href={buildHref(basePath, searchParams, nextOffset)}
          >
            Next
          </Link>
        ) : (
          <span className="button button--secondary" aria-disabled="true">
            Next
          </span>
        )}
      </div>
    </nav>
  );
}
