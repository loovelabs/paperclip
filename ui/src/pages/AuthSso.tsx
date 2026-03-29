/**
 * LOOVE SSO Auth page.
 *
 * When Supabase SSO is enabled, this page replaces the email/password form.
 * It detects whether the user has a valid session (via the loove_auth_token cookie)
 * and either redirects to the target page or shows a "Sign in via LOOVE" button
 * that redirects to loove.io/login.
 */

import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { authApi } from "../api/auth";

const LOOVE_LOGIN_URL = "https://loove.io/login";

export function AuthSsoPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const next = searchParams.get("next") ?? "/";
  const [checking, setChecking] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function checkSession() {
      try {
        const session = await authApi.getSession();
        if (!cancelled && session) {
          navigate(next, { replace: true });
          return;
        }
      } catch {
        // No session – show login button
      }
      if (!cancelled) setChecking(false);
    }

    void checkSession();
    return () => {
      cancelled = true;
    };
  }, [navigate, next]);

  const handleLogin = () => {
    const callbackUrl = `${window.location.origin}${window.location.pathname}?next=${encodeURIComponent(next)}`;
    window.location.href = `${LOOVE_LOGIN_URL}?redirect_to=${encodeURIComponent(callbackUrl)}`;
  };

  if (checking) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background text-foreground">
        <div className="text-center">
          <div className="mb-4 text-lg font-medium">Checking authentication...</div>
          <div className="text-sm text-muted-foreground">
            Verifying your LOOVE session
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background text-foreground">
      <div className="w-full max-w-sm space-y-6 px-4">
        <div className="text-center">
          <h1 className="text-2xl font-semibold tracking-tight">
            Paperclip
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Sign in with your LOOVE account to continue
          </p>
        </div>

        {error && (
          <div className="rounded-md border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm text-destructive">
            {error}
          </div>
        )}

        <button
          type="button"
          onClick={handleLogin}
          className="flex w-full items-center justify-center gap-2 rounded-md bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
        >
          <svg
            className="h-4 w-4"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
            <polyline points="10 17 15 12 10 7" />
            <line x1="15" y1="12" x2="3" y2="12" />
          </svg>
          Sign in with LOOVE
        </button>

        <p className="text-center text-xs text-muted-foreground">
          You'll be redirected to{" "}
          <a
            href="https://loove.io"
            className="underline hover:text-foreground"
            target="_blank"
            rel="noopener noreferrer"
          >
            loove.io
          </a>{" "}
          to authenticate
        </p>
      </div>
    </div>
  );
}
