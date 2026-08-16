import type { Metadata } from "next";
import { listPendingAccountRequests } from "@/lib/account-requests";
import { RequestRow } from "@/components/request-row";

export const metadata: Metadata = {
  title: "Requests",
};

export default async function RequestsPage() {
  const requests = await listPendingAccountRequests();

  return (
    <>
      <section className="page-heading" aria-labelledby="requests-title">
        <h1 id="requests-title">Account requests</h1>
        <p>Review and decide pending account requests.</p>
      </section>

      {requests.length === 0 ? (
        <p role="status">No pending account requests.</p>
      ) : (
        <table className="data-table" aria-label="Pending account requests">
          <thead>
            <tr>
              <th scope="col">Email</th>
              <th scope="col">Username</th>
              <th scope="col">Requested</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {requests.map((request) => (
              <RequestRow key={request.id} request={request} />
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
