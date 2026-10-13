export const publicApiUrl =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

export async function browserApi(path: string, init?: RequestInit): Promise<Response> {
  return fetch(`${publicApiUrl}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      ...init?.headers,
    },
  });
}

export async function readApiError(response: Response): Promise<string> {
  try {
    const payload = (await response.json()) as { detail?: string };
    return payload.detail ?? "Não foi possível concluir a operação.";
  } catch {
    return "Não foi possível concluir a operação.";
  }
}
