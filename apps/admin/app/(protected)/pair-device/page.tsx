import type { Metadata } from "next";
import { getDevicePairing } from "@/lib/pairing";

export const metadata: Metadata = {
  title: "Pair a device",
};

export default async function PairDevicePage() {
  const pairing = await getDevicePairing();

  return (
    <>
      <section className="page-heading" aria-labelledby="pair-device-title">
        <h1 id="pair-device-title">Pair a device</h1>
        <p>
          The Nebula app has no server built in. On first launch it asks for
          this link, then checks that the server it reaches is this deployment
          before anyone signs in.
        </p>
      </section>

      <section className="status-card" aria-labelledby="pair-device-qr">
        <h2 id="pair-device-qr">Scan or share</h2>
        {/* eslint-disable-next-line @next/next/no-img-element -- an inline data URL, nothing to optimise */}
        <img
          src={pairing.qrImage}
          alt="QR code of the pairing link"
          width={240}
          height={240}
        />
        <p>
          Send the link below to the person, or let them scan the code. Paste it
          into the app&apos;s first screen.
        </p>
        <p className="mfa-secret">{pairing.link}</p>
      </section>

      <section className="status-card" aria-labelledby="pair-device-trust">
        <h2 id="pair-device-trust">What the link proves</h2>
        <dl>
          <dt>Deployment</dt>
          <dd>
            <code>{pairing.deploymentId}</code>
          </dd>
          <dt>Certificate authority</dt>
          <dd>
            {pairing.caSha256 ? (
              <>
                This installation issues its own certificate. The app trusts
                only the CA with SHA-256 <code>{pairing.caSha256}</code>, so
                share the link itself, not just the address.
              </>
            ) : (
              <>
                A publicly trusted certificate. The app can also be paired by
                typing this server&apos;s address.
              </>
            )}
          </dd>
        </dl>
        <p>
          The link holds no password or account. It tells the app which server
          to trust. Accounts are still requested and approved as before.
        </p>
      </section>
    </>
  );
}
