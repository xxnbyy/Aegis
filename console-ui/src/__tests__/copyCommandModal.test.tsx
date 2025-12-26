import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import CopyCommandModal from "../components/CopyCommandModal";

describe("CopyCommandModal", () => {
  it("does not write clipboard before acknowledgement", async () => {
    const writeText = vi.fn(async () => undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    const onClose = vi.fn();
    render(
      <CopyCommandModal command={"rm -rf /"} open={true} onClose={onClose} />
    );

    const copyBtn = screen.getByRole("button", { name: "Copy to Clipboard" });
    expect(copyBtn).toBeDisabled();
    expect(writeText).not.toHaveBeenCalled();

    fireEvent.click(screen.getByLabelText("ack"));
    expect(copyBtn).toBeEnabled();

    fireEvent.click(copyBtn);
    await vi.waitFor(() => expect(writeText).toHaveBeenCalledWith("rm -rf /"));
    expect(onClose).toHaveBeenCalled();
  });
});

