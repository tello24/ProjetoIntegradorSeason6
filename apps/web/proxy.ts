import { type NextRequest, NextResponse } from "next/server";

const protectedRoutes = [
  "/dashboard",
  "/scan",
  "/assets",
  "/vulnerabilities",
  "/remediation",
  "/access",
  "/reports",
];

export function proxy(request: NextRequest) {
  const path = request.nextUrl.pathname;
  const isProtected = protectedRoutes.some(
    (route) => path === route || path.startsWith(`${route}/`),
  );
  const hasSession = Boolean(request.cookies.get("ng_session")?.value);

  if (isProtected && !hasSession) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("next", path);
    return NextResponse.redirect(loginUrl);
  }

  if (path === "/login" && hasSession) {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/scan/:path*",
    "/assets/:path*",
    "/vulnerabilities/:path*",
    "/remediation/:path*",
    "/access/:path*",
    "/reports/:path*",
    "/login",
  ],
};
