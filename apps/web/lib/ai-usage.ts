export interface AIUsage {
  analyses: number;
  input_tokens: number;
  output_tokens: number;
  estimated_cost_usd: number;
}

export const formatAITokens = (value: number) => value.toLocaleString("pt-BR");
export const formatAICost = (value: number) => new Intl.NumberFormat("pt-BR", {
  style: "currency", currency: "USD", minimumFractionDigits: 6, maximumFractionDigits: 8,
}).format(value);
export const formatAIDate = (value: string | null) => value ? new Intl.DateTimeFormat("pt-BR", {
  dateStyle: "short", timeStyle: "short", timeZone: "America/Sao_Paulo",
}).format(new Date(value)) : "Nenhuma análise salva";
