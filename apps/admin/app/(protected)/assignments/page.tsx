import type { Metadata } from "next";
import Link from "next/link";
import { listAllAssignments } from "@/lib/access";
import { DataTable } from "@/components/data-table";
import { EmptyState } from "@/components/empty-state";
import { PaginationControls } from "@/components/pagination-controls";

export const metadata: Metadata = {
  title: "Assignments",
};

const PAGE_SIZE = 25;

export default async function AssignmentsPage({
  searchParams,
}: {
  searchParams: Promise<{ offset?: string }>;
}) {
  const params = await searchParams;
  const offset = Number(params.offset ?? 0) || 0;
  const page = await listAllAssignments({ limit: PAGE_SIZE, offset });

  return (
    <>
      <section className="page-heading" aria-labelledby="assignments-title">
        <h1 id="assignments-title">Assignments</h1>
        <p>Assign devices and users to specific VPN servers.</p>
      </section>

      {page.items.length === 0 ? (
        <EmptyState title="Server assignments" status="not-connected">
          <p>
            No users have been assigned to a VPN server yet. Assign one from a
            user&rsquo;s detail page.
          </p>
        </EmptyState>
      ) : (
        <>
          <DataTable
            caption="Assignments"
            headers={["User", "Server", "State", "Assigned", "Expires"]}
            emptyMessage="No server assignments exist."
            rows={page.items.map((item) => ({
              key: item.id,
              cells: [
                <Link key={item.id} href={`/users/${item.userId}`}>
                  {item.userEmail}
                </Link>,
                item.serverDisplayName,
                item.state,
                new Date(item.assignedAt).toLocaleString(),
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
            basePath="/assignments"
            searchParams={{}}
          />
        </>
      )}
    </>
  );
}
