import type { Metadata } from "next";

import { VulnerabilityWorkspace } from "@/components/vulnerability-workspace";

export const metadata: Metadata = {
  title: "Vulnerabilidades",
};

export default function VulnerabilitiesPage() {
  return <VulnerabilityWorkspace />;
}
