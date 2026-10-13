import type { Metadata } from "next";

import { RemediationQueueWorkspace } from "@/components/remediation-queue-workspace";

export const metadata: Metadata = {
  title: "Fila de remediação",
};

export default function RemediationQueuePage() {
  return <RemediationQueueWorkspace />;
}
