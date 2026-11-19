import type { Metadata } from "next";
import { JiraAdminWorkspace } from "@/components/jira-admin-workspace";

export const metadata: Metadata = { title: "Integração Jira" };

export default function JiraAdminPage() { return <JiraAdminWorkspace />; }
