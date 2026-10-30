import Link from "next/link";

type StatTileProps = Readonly<{
  label: string;
  value: number;
  href: string;
}>;

export function StatTile({ label, value, href }: StatTileProps) {
  return (
    <Link className="stat-tile" href={href}>
      <span className="stat-tile__value">{value}</span>
      <span className="stat-tile__label">{label}</span>
    </Link>
  );
}
