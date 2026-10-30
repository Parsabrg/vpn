import type { Metadata } from "next";
import Link from "next/link";
import { listUsers } from "@/lib/users";
import { DataTable } from "@/components/data-table";
import { FilterBar, type FilterField } from "@/components/filter-bar";
import { PaginationControls } from "@/components/pagination-controls";

export const metadata: Metadata = {
  title: "Users",
};

const PAGE_SIZE = 25;

const STATES = ["pending_activation", "active", "suspended", "disabled"];

const FILTER_FIELDS: FilterField[] = [
  {
    name: "state",
    label: "State",
    type: "select",
    options: STATES.map((value) => ({ value, label: value })),
  },
  { name: "email_prefix", label: "Email starts with", type: "text" },
  { name: "username_prefix", label: "Username starts with", type: "text" },
];

interface UsersSearchParams {
  state?: string;
  email_prefix?: string;
  username_prefix?: string;
  offset?: string;
}

export default async function UsersPage({
  searchParams,
}: {
  searchParams: Promise<UsersSearchParams>;
}) {
  const params = await searchParams;
  const offset = Number(params.offset ?? 0) || 0;
  const filterValues = {
    state: params.state,
    email_prefix: params.email_prefix,
    username_prefix: params.username_prefix,
  };

  const page = await listUsers({
    ...(params.state ? { state: params.state } : {}),
    ...(params.email_prefix ? { emailPrefix: params.email_prefix } : {}),
    ...(params.username_prefix
      ? { usernamePrefix: params.username_prefix }
      : {}),
    limit: PAGE_SIZE,
    offset,
  });

  return (
    <>
      <section className="page-heading" aria-labelledby="users-title">
        <h1 id="users-title">Users</h1>
        <p>Search and review user accounts.</p>
      </section>

      <FilterBar fields={FILTER_FIELDS} values={filterValues} />

      <DataTable
        caption="Users"
        headers={["Email", "Username", "State", "Device limit", "Created"]}
        emptyMessage="No users match these filters."
        rows={page.items.map((user) => ({
          key: user.id,
          cells: [
            <Link key={user.id} href={`/users/${user.id}`}>
              {user.email}
            </Link>,
            user.username ?? "—",
            user.state,
            user.deviceLimit,
            new Date(user.createdAt).toLocaleString(),
          ],
        }))}
      />

      <PaginationControls
        total={page.total}
        limit={page.limit}
        offset={page.offset}
        basePath="/users"
        searchParams={filterValues}
      />
    </>
  );
}
