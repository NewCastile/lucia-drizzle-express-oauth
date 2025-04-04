import { type InferSelectModel } from "drizzle-orm";
import {
  pgTable,
  varchar,
  integer,
  timestamp,
  text,
} from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm/relations";

export const userTable = pgTable("user", {
  id: varchar("id", {
    length: 255,
  })
    .notNull()
    .primaryKey()
    .$defaultFn(() => crypto.randomUUID()),
  twitchUserId: varchar("twitchUserId", {
    length: 255,
  }).unique(),
  twitchUsername: varchar("twitcheUsername", {
    length: 255,
  }).unique(),
});

export const sessionTable = pgTable("session", {
  id: varchar("id", {
    length: 255,
  })
    .notNull()
    .primaryKey()
    .$defaultFn(() => crypto.randomUUID()),
  userId: varchar("user_id", { length: 255 })
    .notNull()
    .references(() => userTable.id),
  expiresAt: timestamp("expires_at").notNull(),
});

export const sessionRelations = relations(sessionTable, ({ one }) => ({
  user: one(userTable, {
    fields: [sessionTable.userId],
    references: [userTable.id],
  }),
}));

export const twitchTokenTable = pgTable("twitch_token", {
  id: varchar("id", {
    length: 255,
  })
    .notNull()
    .primaryKey()
    .$defaultFn(() => crypto.randomUUID()),
  userId: varchar("userId", { length: 255 })
    .notNull()
    .references(() => userTable.id),
  access_token: varchar("access_token", { length: 255 }).notNull(),
  refresh_token: varchar("refresh_token", { length: 255 }),
  expires_in: integer("expires_in").notNull(),
  token_type: text("token_type").notNull(),
  scope: text("scope").array(),
});

export const twitchTokenRelations = relations(twitchTokenTable, ({ one }) => ({
  user: one(userTable, {
    fields: [twitchTokenTable.userId],
    references: [userTable.id],
  }),
}));

export type User = InferSelectModel<typeof userTable>;
export type Session = InferSelectModel<typeof sessionTable>;
export type TwitchToken = InferSelectModel<typeof twitchTokenTable>;
