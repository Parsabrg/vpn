"use client";

import type { ReactNode } from "react";
import { useMediaQuery } from "@/lib/use-media-query";

interface DataTableRow {
  key: string;
  cells: ReactNode[];
}

interface DataTableProps {
  caption: string;
  headers: string[];
  rows: DataTableRow[];
  emptyMessage: string;
}

/**
 * Switches to a card layout via useMediaQuery rather than CSS alone: jsdom
 * does not evaluate media queries, so a CSS-only breakpoint would be real in
 * the browser but untestable here.
 */
export function DataTable({
  caption,
  headers,
  rows,
  emptyMessage,
}: DataTableProps) {
  const isNarrow = useMediaQuery("(max-width: 48rem)");

  if (rows.length === 0) {
    return <p role="status">{emptyMessage}</p>;
  }

  if (isNarrow) {
    return (
      <ul className="data-table data-table--cards" aria-label={caption}>
        {rows.map((row) => (
          <li className="data-table__card" key={row.key}>
            {headers.map((header, index) => (
              <div className="data-table__card-field" key={header}>
                <span className="data-table__card-label">{header}</span>
                <span>{row.cells[index]}</span>
              </div>
            ))}
          </li>
        ))}
      </ul>
    );
  }

  return (
    <table className="data-table" aria-label={caption}>
      <thead>
        <tr>
          {headers.map((header) => (
            <th scope="col" key={header}>
              {header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.key}>
            {row.cells.map((cell, index) => (
              <td key={headers[index]}>{cell}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
