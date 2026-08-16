import type { Metadata } from "next";
import { listEmailDeliveries } from "@/lib/email-deliveries";
import { DataTable } from "@/components/data-table";
import { FilterBar, type FilterField } from "@/components/filter-bar";
import { PaginationControls } from "@/components/pagination-controls";

export const metadata: Metadata = {
  title: "Email deliveries",
};

const PAGE_SIZE = 25;

/** Mirrors the closed vocabulary in services/api/src/nebula_api/models/operations.py. */
const STATES = ["pending", "sending", "sent", "failed", "cancelled"];
const TEMPLATE_CODES = [
  "account_request_review",
  "user_activation",
  "password_reset",
  "request_rejected",
];
const SUBJECT_KINDS = ["account_request", "user", "admin"];

const FILTER_FIELDS: FilterField[] = [
  {
    name: "state",
    label: "State",
    type: "select",
    options: STATES.map((value) => ({ value, label: value })),
  },
  {
    name: "template_code",
    label: "Template",
    type: "select",
    options: TEMPLATE_CODES.map((value) => ({ value, label: value })),
  },
  {
    name: "subject_kind",
    label: "Subject kind",
    type: "select",
    options: SUBJECT_KINDS.map((value) => ({ value, label: value })),
  },
];

interface EmailDeliverySearchParams {
  state?: string;
  template_code?: string;
  subject_kind?: string;
  offset?: string;
}

export default async function EmailDeliveriesPage({
  searchParams,
}: {
  searchParams: Promise<EmailDeliverySearchParams>;
}) {
  const params = await searchParams;
  const offset = Number(params.offset ?? 0) || 0;
  const filterValues = {
    state: params.state,
    template_code: params.template_code,
    subject_kind: params.subject_kind,
  };

  const page = await listEmailDeliveries({
    ...(params.state ? { state: params.state } : {}),
    ...(params.template_code ? { templateCode: params.template_code } : {}),
    ...(params.subject_kind ? { subjectKind: params.subject_kind } : {}),
    limit: PAGE_SIZE,
    offset,
  });

  return (
    <>
      <section
        className="page-heading"
        aria-labelledby="email-deliveries-title"
      >
        <h1 id="email-deliveries-title">Email deliveries</h1>
        <p>Delivery status for account-request and user emails.</p>
      </section>

      <FilterBar fields={FILTER_FIELDS} values={filterValues} />

      <DataTable
        caption="Email deliveries"
        headers={[
          "Recipient",
          "Template",
          "Subject",
          "State",
          "Attempts",
          "Sent",
          "Result",
        ]}
        emptyMessage="No email deliveries match these filters."
        rows={page.items.map((item) => ({
          key: item.id,
          cells: [
            item.recipientAddress,
            item.templateCode,
            `${item.subjectKind} (${item.subjectId})`,
            item.state,
            item.attemptCount,
            item.sentAt ? new Date(item.sentAt).toLocaleString() : "—",
            item.resultCode ?? "—",
          ],
        }))}
      />

      <PaginationControls
        total={page.total}
        limit={page.limit}
        offset={page.offset}
        basePath="/email-deliveries"
        searchParams={filterValues}
      />
    </>
  );
}
