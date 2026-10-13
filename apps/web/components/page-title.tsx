import type { ReactNode } from "react";

interface PageTitleProps {
  eyebrow?: string;
  title: string;
  description: string;
  action?: ReactNode;
}

export function PageTitle({ eyebrow, title, description, action }: PageTitleProps) {
  return (
    <header className="page-title">
      <div>
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action && <div className="page-title__action">{action}</div>}
    </header>
  );
}
