import type { Metadata } from "next";

import {
  AssetWorkspace,
  type AssetListResponse,
} from "@/components/asset-workspace";
import { serverApi } from "@/lib/api-server";

export const metadata: Metadata = {
  title: "Ativos",
};

export default async function AssetsPage() {
  const inventory = await serverApi<AssetListResponse>("/assets");
  return <AssetWorkspace initialData={inventory} />;
}
