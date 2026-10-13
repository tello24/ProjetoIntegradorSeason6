import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

const internalApiUrl =
  process.env.INTERNAL_API_URL ??
  process.env.NEXT_PUBLIC_API_URL ??
  "http://localhost:8000/api/v1";

export async function serverApi<T>(path: string): Promise<T> {
  const cookieStore = await cookies();
  const session = cookieStore.get("ng_session");
  if (!session) {
    redirect("/login");
  }

  const response = await fetch(`${internalApiUrl}${path}`, {
    cache: "no-store",
    headers: {
      Cookie: `${session.name}=${session.value}`,
    },
  });

  if (response.status === 401) {
    redirect("/login");
  }
  if (!response.ok) {
    throw new Error(`API respondeu com status ${response.status}.`);
  }
  return (await response.json()) as T;
}
