import { generateState, Twitch } from "arctic";
import express, { Request, response, Response } from "express";
import cookieParser from "cookie-parser";
import {
  createSession,
  deleteSessionTokenCookie,
  generateSessionToken,
  invalidateSession,
  setSessionTokenCookie,
  validateSessionToken,
} from "./utils/session";
import { drizzle } from "drizzle-orm/node-postgres";
import * as schema from "./db/schema";
import { twitchTokenTable, User, userTable } from "./db/schema";
import { eq } from "drizzle-orm";

process.loadEnvFile();

const uri = process.env.DATABASE_URL;

const app = express();
const port = 3000;

export const db = drizzle(uri!, { schema });
export const clientId = process.env.TWITCH_CLIENT_ID;
export const clientSecret = process.env.TWITCH_CLIENT_SECRET;
export const loginRedirectUri = `http://localhost:${port}/login/callback`;

const twitchTokenUri = "https://id.twitch.tv/oauth2/token";

export const twitch = new Twitch(clientId!, clientSecret!, loginRedirectUri);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const renderLoginPage = ({ state }: { state: string }) => {
  const url = twitch.createAuthorizationURL(state, [
    "channel:read:polls",
    "channel:manage:polls",
  ]);

  url.searchParams.set("force_verify", "true");
  url.searchParams.set(
    "claims",
    `{"id_token":{"email":null,"email_verified":null},"userinfo":{"aud":null,"exp":null,"iat":null,"iss":null,"sub":null,"email":null,"email_verified":null,"preferred_username":null,"picture":null,"updated_at":null}}`
  );
  url.searchParams.set("nonce", state);

  return `
    <a href="https://id.twitch.tv/oauth2/authorize?response_type=code&client_id=${clientId!}&redirect_uri=${loginRedirectUri!}&scope=channel%3Amanage%3Apolls+channel%3Aread%3Apolls&state=${state}&nonce=${state}&force_verify=true&claims=">
      Login with Twitch
    </a>
  `;
};

const renderWelcomePage = ({ user }: { user: User }) => {
  return `
    <p>you logged in as ${user.twitchUsername}</p>
    <a href="/app">App</a>
    <a href="/">Home</a>
    <form action="/logout" method="post">
      <button type="submit">Logout</button>
    </form>
  `;
};

// respond with "hello world" when a GET request is made to the homepage
app.get("/hello-world", function (_req, res) {
  res.send("hello world");
});

app.get("/login", function (req, res) {
  const state = generateState();
  // Getting claims information from an access token
  // To get the claims information from an access token, send an HTTP GET request to the /userinfo endpoint.
  // You may call this endpoint only with an OAuth access token; you may not call it using an ID token.
  if ("error" in req.query) {
    res.send(
      `<p>error: ${req.query.error}</p>
       <p>error_description: ${req.query.error_description}</p>
       ${renderLoginPage({ state })}
      `
    );
    return;
  }
  res.send(renderLoginPage({ state }));
});

app.get("/app", async (req, res) => {
  const session = await getCurrentSession(req, res);

  if (!session) {
    console.error("Internal server error");
    console.log(session);

    res.redirect("/login");
  } else {
    const { user } = session;

    res.send(renderWelcomePage({ user }));
  }
});

app.get("/", async (req, res) => {
  const session = await getCurrentSession(req, res);

  if (!session) {
    console.error("Internal server error");
    console.log(session);

    res.redirect("/login");
  } else {
    const { user } = session;

    res.send(renderWelcomePage({ user }));
  }
});

app.post("/logout", async function (req, res) {
  const session = await getCurrentSession(req, res);

  if (!session) {
    console.error("Internal server error");
    console.log(session);

    res.redirect("/login");
  } else {
    await invalidateSession({ sessionId: session.session.id });

    res.redirect("/");
  }
});

app.get(
  "/login/callback",
  async (req: Request<{}, {}, {}, TwitchLoginRedirectURIQueryParams>, res) => {
    console.log("Login callback");

    if ("code" in req.query && "scope" in req.query) {
      const { code } = req.query;

      let body = new URLSearchParams({
        client_id: clientId!,
        client_secret: clientSecret!,
        code: code!,
        redirect_uri: loginRedirectUri,
        grant_type: "authorization_code",
      });

      const response = await fetch(twitchTokenUri, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body,
      });

      const token: unknown = await response.json();

      if (!IsTwitchTokenResponse(token)) {
        res.send("Error");
        return;
      }

      const { access_token } = token;

      const userinfoResponse = await fetch(
        "https://id.twitch.tv/oauth2/userinfo",
        {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${access_token}`,
          },
        }
      );

      const twitchUserInfo: unknown = await userinfoResponse.json();

      if (!IsTwitchUserInfoResponse(twitchUserInfo)) {
        res.send("Error");
        return;
      }

      const { sub, preferred_username } = twitchUserInfo;

      const user = await getUserFromDBByTwitchUserId({ twitchUserId: sub });

      if (user) {
        const upsertTwitchTokenRes = await upsertTwitchToken({
          token,
          userId: user.id,
        });

        const sessionToken = generateSessionToken();

        const session = await createSession({
          token: sessionToken,
          userId: user.id,
        });

        setSessionTokenCookie(res, sessionToken, session.expiresAt);
        return res.redirect("/");
      } else {
        const insertUserRes = await insertUser({
          twitchUserId: sub,
          twitchUsername: preferred_username ?? null,
        });

        const { id: userId } = insertUserRes;

        await upsertTwitchToken({
          userId,
          token,
        });

        const sessionToken = generateSessionToken();

        const session = await createSession({
          token: sessionToken,
          userId: insertUserRes.id,
        });

        setSessionTokenCookie(res, sessionToken, session.expiresAt);

        res.redirect("/");
      }
    }
  }
);

app.listen(port, () => {
  console.log(`Example app listening on port ${port}!`);
});

const getCurrentSession = async (req: Request, res: Response) => {
  // csrf protection
  if (req.method === "GET") {
    const origin = req.headers.host;

    if (!origin || origin === `http://localhost:${port}`) {
      // unknown origin
      res.statusCode = 200;
      res.statusMessage = "unknown origin";
      return null;
    }
  }

  // session validation
  const cookies = req.cookies;

  if ("session" in cookies && !cookies.session) {
    // unauthorized
    res.statusCode = 401;
    res.statusMessage = "unauthorized";
    return null;
  }

  const token = cookies.session as string;

  const { session, user } = await validateSessionToken({ token });

  if (!session) {
    deleteSessionTokenCookie(res);
    // unauthorized
    res.statusCode = 401;
    res.statusMessage = "unauthorized";
    return null;
  }

  setSessionTokenCookie(res, token, session.expiresAt);

  return { user, session };
};

// #region DB Queries
const getUserFromDBByTwitchUserId = async ({
  twitchUserId,
}: {
  twitchUserId: string;
}) => {
  const user = await db.query.userTable.findFirst({
    where: eq(userTable.twitchUserId, twitchUserId),
  });

  if (!user) {
    console.log(`User with twitch user id: ${twitchUserId} not found`);
    return null;
  }

  return user;
};

const insertUser = async ({
  twitchUserId,
  twitchUsername,
}: Omit<schema.User, "id">) => {
  const [res] = await db
    .insert(userTable)
    .values({
      twitchUserId,
      twitchUsername,
    })
    .returning();

  return res;
};

const upsertTwitchToken = async ({
  userId,
  token,
}: {
  userId: string;
  token: TwitchTokenResponse;
}) => {
  const twitchToken = await db.query.twitchTokenTable.findFirst({
    where: ({}, { eq, and }) =>
      and(
        eq(twitchTokenTable.access_token, token.access_token),
        eq(twitchTokenTable.userId, userId)
      ),
  });

  if (twitchToken) {
    const [upsertRes] = await db
      .update(schema.twitchTokenTable)
      .set(token)
      .where(eq(schema.twitchTokenTable.id, twitchToken.id))
      .returning();

    return upsertRes;
  }

  const { access_token, refresh_token, expires_in, scope, token_type } = token;

  const [res] = await db
    .insert(schema.twitchTokenTable)
    .values({
      access_token,
      refresh_token,
      expires_in,
      scope,
      token_type,
      userId,
    })
    .returning();

  return res;
};

// #endregion

// #region Types
interface TwitchUserInfoResponse {
  aud: string;
  exp: number;
  iat: number;
  iss: string;
  sub: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
  preferred_username?: string;
  updated_at?: string;
}

interface TwitchTokenResponse {
  access_token: string;
  expires_in: number;
  refresh_token: string;
  scope: string[];
  token_type: string;
}

interface TwitchLoginRedirectURIQueryParams {
  code?: string;
  scope?: string;
  error?: string;
  error_description?: string;
  state: string;
}

const IsTwitchTokenResponse = (
  response: unknown
): response is TwitchTokenResponse => {
  return (
    response !== null &&
    typeof (response as TwitchTokenResponse).access_token === "string"
  );
};

const IsTwitchUserInfoResponse = (
  res: unknown
): res is TwitchUserInfoResponse => {
  return (
    response !== null && typeof (res as TwitchUserInfoResponse).sub === "string"
  );
};
