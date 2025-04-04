import {
  encodeBase32LowerCaseNoPadding,
  encodeHexLowerCase,
} from "@oslojs/encoding";
import { sha256 } from "@oslojs/crypto/sha2";
import { Response, Request } from "express";
import { Session, sessionTable, User } from "../db/schema";
import { db } from "../server";
import { eq } from "drizzle-orm";

const SESSION_ADD_TIME = 1000 * 60 * 60 * 24 * 30;
const SESSION_APPROXIMATE_EXPIRATION_TIME = 1000 * 60 * 60 * 24 * 15;

export const createSession = async ({
  token,
  userId,
}: {
  token: string;
  userId: string;
}): Promise<Session> => {
  const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));

  const session: Session = {
    id: sessionId,
    userId,
    expiresAt: new Date(Date.now() + SESSION_ADD_TIME),
  };

  const res = await db.insert(sessionTable).values(session).returning();

  return session;
};

export const validateSessionToken = async ({
  token,
}: {
  token: string;
}): Promise<SessionValidationResult> => {
  const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));

  const res = await db.query.sessionTable.findFirst({
    where: ({ id }, { eq }) => eq(id, sessionId),
    with: {
      user: true,
    },
  });

  if (!res) {
    return { session: null, user: null };
  }

  const { user, ...session } = res;

  if (!user) return { session: null, user: null };

  // Refresh twitch session token
  if (Date.now() >= session.expiresAt.getTime()) {
    await db.delete(sessionTable).where(eq(sessionTable.id, session.id));

    return { session: null, user: null };
  }

  if (
    Date.now() >=
    session.expiresAt.getTime() - SESSION_APPROXIMATE_EXPIRATION_TIME
  ) {
    const newExpirationTime = new Date(Date.now() + SESSION_ADD_TIME);

    session.expiresAt = newExpirationTime;

    await db
      .update(sessionTable)
      .set({ expiresAt: session.expiresAt })
      .where(eq(sessionTable.id, session.id))
      .returning();
  }

  return { session, user };
};

export const invalidateSession = async ({
  sessionId,
}: {
  sessionId: string;
}): Promise<void> => {
  await db.delete(sessionTable).where(eq(sessionTable.id, sessionId));
};

export const invalidateAllSessions = async ({
  userId,
}: {
  userId: string;
}): Promise<void> => {
  const res = await db
    .delete(sessionTable)
    .where(eq(sessionTable.userId, userId));
};

export const generateSessionToken = (): string => {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  const token = encodeBase32LowerCaseNoPadding(bytes);

  return token;
};

export const setSessionTokenCookie = (
  res: Response,
  token: string,
  expiresAt: Date
): void => {
  if (process.env.NODE_ENV === "production") {
    // When deployed over HTTPS
    res.append(
      "Set-Cookie",
      `session=${token}; HttpOnly; SameSite=Lax; Expires=${expiresAt.toUTCString()}; Path=/; Secure;`
    );
  } else {
    // When deployed over HTTP (localhost)
    res.append(
      "Set-Cookie",
      `session=${token}; HttpOnly; SameSite=Lax; Expires=${expiresAt.toUTCString()}; Path=/`
    );
  }
};

export const deleteSessionTokenCookie = (res: Response): void => {
  if (process.env.NODE_ENV === "production") {
    // When deployed over HTTPS
    res.append(
      "Set-Cookie",
      "session=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/; Secure;"
    );
  } else {
    // When deployed over HTTP (localhost)
    res.append(
      "Set-Cookie",
      "session=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/"
    );
  }
};

export type SessionValidationResult =
  | { session: Session; user: User }
  | { session: null; user: null };
