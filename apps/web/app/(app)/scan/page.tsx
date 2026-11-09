import type { Metadata } from "next";

import {
  ScanWorkspace,
  type ScanItem,
  type ScannerSource,
} from "@/components/scan-workspace";
import { serverApi } from "@/lib/api-server";

export const metadata: Metadata = {
  title: "Scans",
};

interface ScanResponse {
  items: ScanItem[];
  total: number;
  can_import: boolean;
  can_delete: boolean;
}

export default async function ScansPage() {
  const [scans, sources] = await Promise.all([
    serverApi<ScanResponse>("/scans"),
    serverApi<ScannerSource[]>("/scans/sources"),
  ]);
  return (
    <ScanWorkspace
      canImport={scans.can_import}
      canDelete={scans.can_delete}
      initialScans={scans.items}
      scannerSources={sources}
    />
  );
}
