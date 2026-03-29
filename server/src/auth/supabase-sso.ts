/**
 * Supabase SSO session resolver for LOOVE edge OAuth.
 *
 * Reads the `loove_auth_token` cookie (or `sb-access-token` / Authorization header)
 * set by loove.io, validates it against the Supabase Auth `/auth/v1/user` endpoint,
 * and maps the identity to Paperclip's internal user tables.
 *
 * This replaces better-auth's session resolver for browser sessions while keeping
 * the existing agent JWT and API key auth paths untouched.
 */

import type { Request, RequestHandler } from "express";
import { eq, and } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import {
  authUsers,
  authSessions,
  instanceUserRoles,
  companyMemberships,
} from "@paperclipai/db";
import { logger } from "../middleware/logger.js";
import type { BetterAuthSessionResult } from "./better-auth.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

interface SupabaseSsoConfig {
  /** e.g. https://ewlygzvnvqyvszdpwbww.supabase.co */
  supabaseUrl: string;
  /** Public anon key – used as apikey header when calling Supabase Auth */
  supabaseAnonKey: string;
  /** Cookie name set by loove.io SSO (defaults to sb-<ref>-auth-token) */
  cookieName?: string;
  /** Loove.io login URL for redirects */
  looveLoginUrl?: string;
}

// ---------------------------------------------------------------------------
// Token extraction helpers
// ---------------------------------------------------------------------------

function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  if (!cookieHeader) return {};
  const cookies: Record<string, string> = {};
  for (const pair of cookieHeader.split(";")) {
    const idx = pair.indexOf("=");
    if (idx < 0) continue;
    const key = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    cookies[key] = decodeURIComponent(value);
  }
  return cookies;
}

/**
 * Extract the Supabase access token from the request.
 * Priority:
 *   1. `loove_auth_token` cookie (set by loove.io edge middleware)
 *   2. `sb-ewlygzvnvqyvszdpwbww-auth-token` cookie (Supabase default)
 *   3. Authorization: Bearer header (for API callers)
 */
function extractAccessToken(req: Request, cookieName: string): string | null {
  const cookies = parseCookies(req.headers.cookie);

  // Primary: loove_auth_token cookie
  if (cookies["loove_auth_token"]) {
    // The cookie may be a JSON-encoded object with access_token inside
    try {
      const parsed = JSON.parse(cookies["loove_auth_token"]);
      if (typeof parsed === "object" && parsed.access_token) {
        return parsed.access_token;
      }
    } catch {
      // Not JSON – treat as raw token
    }
    return cookies["loove_auth_token"];
  }

  // Secondary: Supabase default cookie (may be base64-encoded JSON)
  if (cookies[cookieName]) {
    try {
      const parsed = JSON.parse(cookies[cookieName]);
      if (typeof parsed === "object" && parsed.access_token) {
        return parsed.access_token;
      }
      // Supabase sometimes stores as an array [access_token, refresh_token]
      if (Array.isArray(parsed) && typeof parsed[0] === "string") {
        return parsed[0];
      }
    } catch {
      // Not JSON
    }
    return cookies[cookieName];
  }

  // Tertiary: Bearer header (only if it looks like a Supabase JWT, not a Paperclip key)
  const authHeader = req.headers.authorization;
  if (authHeader?.toLowerCase().startsWith("bearer ")) {
    const token = authHeader.slice(7).trim();
    // Supabase JWTs have 3 dot-separated parts and start with eyJ
    if (token.startsWith("eyJ") && token.split(".").length === 3) {
      return token;
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Supabase user verification (calls /auth/v1/user)
// ---------------------------------------------------------------------------

interface SupabaseUser {
  id: string;
  email?: string;
  user_metadata?: {
    full_name?: string;
    name?: string;
    display_name?: string;
  };
}

/** In-memory cache to avoid hitting Supabase on every request */
const tokenCache = new Map<string, { user: SupabaseUser; expiresAt: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

async function verifySupabaseToken(
  supabaseUrl: string,
  anonKey: string,
  accessToken: string,
): Promise<SupabaseUser | null> {
  // Check cache first
  const cached = tokenCache.get(accessToken);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.user;
  }

  try {
    const res = await fetch(`${supabaseUrl}/auth/v1/user`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        apikey: anonKey,
      },
    });

    if (!res.ok) {
      if (res.status === 401) {
        tokenCache.delete(accessToken);
        return null;
      }
      logger.warn(
        { status: res.status, url: `${supabaseUrl}/auth/v1/user` },
        "Supabase user verification returned non-OK status",
      );
      return null;
    }

    const user = (await res.json()) as SupabaseUser;
    if (!user?.id) return null;

    // Cache the result
    tokenCache.set(accessToken, { user, expiresAt: Date.now() + CACHE_TTL_MS });

    // Evict stale entries periodically
    if (tokenCache.size > 1000) {
      const now = Date.now();
      for (const [key, entry] of tokenCache) {
        if (entry.expiresAt < now) tokenCache.delete(key);
      }
    }

    return user;
  } catch (err) {
    logger.error({ err }, "Failed to verify Supabase access token");
    return null;
  }
}

// ---------------------------------------------------------------------------
// User upsert – ensure the Supabase user exists in Paperclip's auth tables
// ---------------------------------------------------------------------------

async function ensurePaperclipUser(
  db: Db,
  supabaseUser: SupabaseUser,
): Promise<string> {
  const userId = supabaseUser.id;
  const email = supabaseUser.email ?? null;
  const name =
    supabaseUser.user_metadata?.full_name ??
    supabaseUser.user_metadata?.name ??
    supabaseUser.user_metadata?.display_name ??
    email ??
    "LOOVE User";

  const existing = await db
    .select({ id: authUsers.id })
    .from(authUsers)
    .where(eq(authUsers.id, userId))
    .then((rows) => rows[0] ?? null);

  const now = new Date();

  if (!existing) {
    await db.insert(authUsers).values({
      id: userId,
      name,
      email: email ?? `${userId}@loove.io`,
      emailVerified: true,
      image: null,
      createdAt: now,
      updatedAt: now,
    });
    logger.info({ userId, email }, "Created Paperclip user from Supabase SSO");
  } else {
    // Update name/email if changed
    await db
      .update(authUsers)
      .set({ name, email: email ?? undefined, updatedAt: now })
      .where(eq(authUsers.id, userId));
  }

  return userId;
}

// ---------------------------------------------------------------------------
// Session resolver (plugs into actorMiddleware's resolveSession slot)
// ---------------------------------------------------------------------------

export function createSupabaseSsoSessionResolver(
  db: Db,
  config: SupabaseSsoConfig,
): (req: Request) => Promise<BetterAuthSessionResult | null> {
  const supabaseRef = new URL(config.supabaseUrl).hostname.split(".")[0];
  const cookieName = config.cookieName ?? `sb-${supabaseRef}-auth-token`;

  return async (req: Request): Promise<BetterAuthSessionResult | null> => {
    const accessToken = extractAccessToken(req, cookieName);
    if (!accessToken) return null;

    const supabaseUser = await verifySupabaseToken(
      config.supabaseUrl,
      config.supabaseAnonKey,
      accessToken,
    );
    if (!supabaseUser) return null;

    const userId = await ensurePaperclipUser(db, supabaseUser);

    return {
      session: {
        id: `supabase-sso:${userId}`,
        userId,
      },
      user: {
        id: userId,
        email: supabaseUser.email ?? null,
        name:
          supabaseUser.user_metadata?.full_name ??
          supabaseUser.user_metadata?.name ??
          null,
      },
    };
  };
}

// ---------------------------------------------------------------------------
// Auth handler – replaces better-auth's /api/auth/* routes
// ---------------------------------------------------------------------------

export function createSupabaseSsoAuthHandler(
  db: Db,
  config: SupabaseSsoConfig,
): RequestHandler {
  const resolveSession = createSupabaseSsoSessionResolver(db, config);
  const looveLoginUrl = config.looveLoginUrl ?? "https://loove.io/login";

  return async (req, res, _next) => {
    const path = (req.params as Record<string, string>).authPath ?? req.path;

    // GET /api/auth/get-session – handled by the synthetic endpoint in app.ts
    // POST /api/auth/sign-out – clear cookies and redirect
    if (path === "sign-out" || path === "/sign-out") {
      // Clear the loove_auth_token cookie
      res.clearCookie("loove_auth_token", { domain: ".loove.io", path: "/" });
      res.json({ success: true, redirect: looveLoginUrl });
      return;
    }

    // POST /api/auth/sign-in/email or sign-up/email – redirect to LOOVE SSO
    if (
      path.includes("sign-in") ||
      path.includes("sign-up") ||
      path === "signin" ||
      path === "signup"
    ) {
      const next = req.query.next ?? req.body?.callbackURL ?? "/";
      res.json({
        redirect: `${looveLoginUrl}?next=${encodeURIComponent(String(next))}`,
        message: "Authentication is handled via LOOVE SSO. Please sign in at loove.io.",
      });
      return;
    }

    // Fallback: return session info if authenticated
    const session = await resolveSession(req);
    if (session) {
      res.json(session);
      return;
    }

    res.status(401).json({
      error: "Unauthorized",
      loginUrl: looveLoginUrl,
    });
  };
}

// ---------------------------------------------------------------------------
// Configuration loader
// ---------------------------------------------------------------------------

export function loadSupabaseSsoConfig(): SupabaseSsoConfig | null {
  const supabaseUrl = process.env.LOOVE_SUPABASE_URL ?? process.env.SUPABASE_URL;
  const anonKey = process.env.LOOVE_SUPABASE_ANON_KEY ?? process.env.SUPABASE_ANON_KEY;

  if (!supabaseUrl || !anonKey) {
    return null;
  }

  return {
    supabaseUrl,
    supabaseAnonKey: anonKey,
    cookieName: process.env.LOOVE_AUTH_COOKIE_NAME,
    looveLoginUrl: process.env.LOOVE_LOGIN_URL ?? "https://loove.io/login",
  };
}
