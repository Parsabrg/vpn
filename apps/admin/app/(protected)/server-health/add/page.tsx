import type { Metadata } from "next";
import { AddServerForm } from "@/components/add-server-form";

export const metadata: Metadata = {
  title: "Add server",
};

export default function AddServerPage() {
  return (
    <>
      <section className="page-heading" aria-labelledby="add-server-title">
        <h1 id="add-server-title">Add server</h1>
        <p>
          A second VPN server, managed from this panel. Users, sign-in and
          backups stay here; the new server only carries traffic.
        </p>
      </section>
      <section className="status-card">
        <AddServerForm />
      </section>
    </>
  );
}
