import type { Metadata } from "next";

import { AccessWorkspace } from "@/components/access-workspace";

export const metadata: Metadata = {
  title: "Controle de acessos",
};

export default function AccessPage() {
  return <AccessWorkspace />;
}
