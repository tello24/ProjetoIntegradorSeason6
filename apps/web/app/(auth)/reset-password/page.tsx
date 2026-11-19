import { PasswordForm } from "@/components/password-form";
export const metadata = { title: "Redefinir senha", referrer: "no-referrer" as const };
export default function Page() { return <PasswordForm mode="reset" />; }
