import type { Metadata } from "next";

import {
  AssetDetailWorkspace,
  type AssetDetail,
} from "@/components/asset-detail-workspace";
import { serverApi } from "@/lib/api-server";

export const metadata: Metadata = {
  title: "Asset 360",
};

export default async function AssetDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const asset = await serverApi<AssetDetail>(`/assets/${id}`);

  return <AssetDetailWorkspace asset={asset} />;
}
