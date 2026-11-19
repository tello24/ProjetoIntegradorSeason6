import { PasswordForm } from "@/components/password-form";
export const metadata = { title: "Recuperar acesso", referrer: "no-referrer" as const };
export default function Page() { return <PasswordForm mode="forgot" />; }
