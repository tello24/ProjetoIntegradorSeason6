import type { Metadata } from "next";

import {
  DashboardWorkspace,
  type DashboardSummary,
} from "@/components/dashboard-workspace";
import { serverApi } from "@/lib/api-server";

export const metadata: Metadata = {
  title: "Dashboard",
};

export default async function DashboardPage() {
  const summary = await serverApi<DashboardSummary>("/dashboard/summary");
  return <DashboardWorkspace initialSummary={summary} />;
}
