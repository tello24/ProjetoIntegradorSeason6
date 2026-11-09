import type { Metadata } from "next";

import { AIAdminWorkspace } from "@/components/ai-admin-workspace";

export const metadata: Metadata = { title: "Administração da IA" };

export default function AIAdminPage() {
  return <AIAdminWorkspace />;
}
