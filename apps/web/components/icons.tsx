import type { SVGProps } from "react";

export type IconName =
  | "assets"
  | "brain"
  | "calendar"
  | "dashboard"
  | "download"
  | "info"
  | "logout"
  | "queue"
  | "report"
  | "scan"
  | "search"
  | "shield"
  | "upload"
  | "users"
  | "vulnerability";

interface IconProps extends SVGProps<SVGSVGElement> {
  name: IconName;
  size?: number;
}

export function Icon({ name, size = 20, ...props }: IconProps) {
  const paths: Record<IconName, React.ReactNode> = {
    assets: (
      <>
        <rect x="3" y="5" width="18" height="14" rx="2" />
        <path d="M7 9h10M7 13h2m3 0h5" />
      </>
    ),
    brain: (
      <>
        <path d="M9.5 4.5a3 3 0 0 0-5 2.2A3.5 3.5 0 0 0 5 13v1a3 3 0 0 0 4.5 2.6" />
        <path d="M14.5 4.5a3 3 0 0 1 5 2.2A3.5 3.5 0 0 1 19 13v1a3 3 0 0 1-4.5 2.6M9.5 4.5v15m5-15v15M7 9h2.5m5 0H17M7 14h2.5m5 0H17" />
      </>
    ),
    calendar: (
      <>
        <rect x="3" y="5" width="18" height="16" rx="2" />
        <path d="M8 3v4m8-4v4M3 10h18M8 14h.01m4 0h.01m4 0h.01M8 18h.01m4 0h.01" />
      </>
    ),
    dashboard: (
      <>
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </>
    ),
    download: (
      <>
        <path d="M12 4v11m-4-4 4 4 4-4" />
        <path d="M4 19h16" />
      </>
    ),
    info: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 11v6m0-10h.01" />
      </>
    ),
    logout: (
      <>
        <path d="M10 17l5-5-5-5m5 5H3" />
        <path d="M15 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4" />
      </>
    ),
    queue: (
      <>
        <path d="M5 6h14M5 12h14M5 18h14" />
        <circle cx="3" cy="6" r=".6" fill="currentColor" stroke="none" />
        <circle cx="3" cy="12" r=".6" fill="currentColor" stroke="none" />
        <circle cx="3" cy="18" r=".6" fill="currentColor" stroke="none" />
      </>
    ),
    report: (
      <>
        <path d="M5 3h10l4 4v14H5V3Z" />
        <path d="M15 3v5h4M8 17v-3m4 3v-6m4 6v-8" />
      </>
    ),
    scan: (
      <>
        <circle cx="11" cy="11" r="7" />
        <path d="m20 20-4-4" />
      </>
    ),
    search: (
      <>
        <circle cx="11" cy="11" r="7" />
        <path d="m20 20-4-4" />
      </>
    ),
    shield: <path d="M12 3 4.5 6v5.5c0 4.7 3 7.9 7.5 9.5 4.5-1.6 7.5-4.8 7.5-9.5V6L12 3Z" />,
    upload: (
      <>
        <path d="M12 16V4m-4 4 4-4 4 4" />
        <path d="M4 14v5a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-5" />
      </>
    ),
    users: (
      <>
        <circle cx="9" cy="8" r="3" />
        <path d="M3.5 19v-1.5A4.5 4.5 0 0 1 8 13h2a4.5 4.5 0 0 1 4.5 4.5V19" />
        <path d="M15.5 5.5a3 3 0 0 1 0 5.5M17 13.5a4 4 0 0 1 3.5 4V19" />
      </>
    ),
    vulnerability: (
      <>
        <path d="M12 3 2.8 19h18.4L12 3Z" />
        <path d="M12 9v4m0 3h.01" />
      </>
    ),
  };

  return (
    <svg
      aria-hidden="true"
      fill="none"
      height={size}
      viewBox="0 0 24 24"
      width={size}
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="1.8"
      {...props}
    >
      {paths[name]}
    </svg>
  );
}
