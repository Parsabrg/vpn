import type { Metadata } from "next";
import Link from "next/link";
import { listAllPermissions } from "@/lib/access";
import { DataTable } from "@/components/data-table";
import { EmptyState } from "@/components/empty-state";
import { PaginationControls } from "@/components/pagination-controls";

export const metadata: Metadata = {
  title: "Permissions",
};

const PAGE_SIZE = 25;

export default async function PermissionsPage({
  searchParams,
}: {
  searchParams: Promise<{ offset?: string }>;
}) {
  const params = await searchParams;
  const offset = Number(params.offset ?? 0) || 0;
  const page = await listAllPermissions({ limit: PAGE_SIZE, offset });

  return (
    <>
      <section className="page-heading" aria-labelledby="permissions-title">
        <h1 id="permissions-title">Permissions</h1>
        <p>Grant and review which users may reach which VPN servers.</p>
      </section>

      {page.items.length === 0 ? (
        <EmptyState title="Permission grants" status="not-connected">
          <p>
            No protocol permissions have been granted yet. Grant one from a
            user&rsquo;s detail page.
          </p>
        </EmptyState>
      ) : (
        <>
          <DataTable
            caption="Permissions"
            headers={["User", "Profile", "State", "Granted", "Expires"]}
            emptyMessage="No protocol permissions are granted."
            rows={page.items.map((item) => ({
              key: item.id,
              cells: [
                <Link key={item.id} href={`/users/${item.userId}`}>
                  {item.userEmail}
                </Link>,
                item.profileDisplayName,
                item.state,
                new Date(item.grantedAt).toLocaleString(),
                item.expiresAt
                  ? new Date(item.expiresAt).toLocaleString()
                  : "—",
              ],
            }))}
          />
          <PaginationControls
            total={page.total}
            limit={page.limit}
            offset={page.offset}
            basePath="/permissions"
            searchParams={{}}
          />
        </>
      )}
    </>
  );
}
