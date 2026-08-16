import { AdminHeader } from "@/components/admin-header";
import { requireAdminSession } from "@/lib/auth/require-session";

export default async function ProtectedLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  const session = await requireAdminSession();

  return (
    <>
      <AdminHeader session={session} />
      <main id="main-content" className="page-shell" tabIndex={-1}>
        {children}
      </main>
    </>
  );
}
