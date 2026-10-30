import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it } from "vitest";
import { ConfirmDialog } from "@/components/confirm-dialog";

function Harness() {
  const [open, setOpen] = useState(false);
  const [confirmedCount, setConfirmedCount] = useState(0);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Open
      </button>
      <p>Confirmed: {confirmedCount}</p>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title="Confirm this"
        confirmLabel="Do it"
        pending={false}
        error={null}
        onConfirm={() => {
          setConfirmedCount((count) => count + 1);
        }}
      >
        <p>Are you sure?</p>
      </ConfirmDialog>
    </>
  );
}

describe("ConfirmDialog", () => {
  it("closes via a keyboard-activated Cancel button without confirming", async () => {
    const user = userEvent.setup();
    render(<Harness />);

    await user.click(screen.getByRole("button", { name: "Open" }));
    expect(screen.getByRole("heading", { name: "Confirm this" })).toBeVisible();

    screen.getByRole("button", { name: "Cancel" }).focus();
    await user.keyboard("{Enter}");

    expect(document.querySelector("dialog")).not.toHaveAttribute("open");
    expect(screen.getByText("Confirmed: 0")).toBeVisible();
  });

  it("confirms via a keyboard-activated submit button", async () => {
    const user = userEvent.setup();
    render(<Harness />);

    await user.click(screen.getByRole("button", { name: "Open" }));
    screen.getByRole("button", { name: "Do it" }).focus();
    await user.keyboard("{Enter}");

    expect(screen.getByText("Confirmed: 1")).toBeVisible();
  });
});
