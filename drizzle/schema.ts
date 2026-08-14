import { int, mysqlEnum, mysqlTable, text, timestamp, varchar, decimal, boolean } from "drizzle-orm/mysql-core";

export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  sdBalance: decimal("sdBalance", { precision: 12, scale: 2 }).default("0.00").notNull(),
  referralCode: varchar("referralCode", { length: 32 }).unique(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export const bots = mysqlTable("bots", {
  id: int("id").autoincrement().primaryKey(), slug: varchar("slug", { length: 64 }).notNull().unique(), name: varchar("name", { length: 120 }).notNull(), vendor: varchar("vendor", { length: 120 }).notNull(), description: text("description").notNull(), capabilities: text("capabilities").notNull(), status: mysqlEnum("status", ["online", "degraded", "offline"]).default("online").notNull(), createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const pairings = mysqlTable("pairings", {
  id: int("id").autoincrement().primaryKey(), userId: int("userId").notNull(), botId: int("botId").notNull(), phoneNumber: varchar("phoneNumber", { length: 32 }).notNull(), pairingCode: varchar("pairingCode", { length: 32 }), status: mysqlEnum("status", ["waiting", "code_generated", "connected", "failed", "disconnected"]).default("waiting").notNull(), lastHeartbeat: timestamp("lastHeartbeat"), connectedAt: timestamp("connectedAt"), createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const telegramKeys = mysqlTable("telegramKeys", {
  id: int("id").autoincrement().primaryKey(), userId: int("userId").notNull(), botId: int("botId").notNull(), keyValue: varchar("keyValue", { length: 96 }).notNull().unique(), telegramUsername: varchar("telegramUsername", { length: 128 }), durationDays: int("durationDays").notNull(), expiresAt: timestamp("expiresAt").notNull(), createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const walletTransactions = mysqlTable("walletTransactions", {
  id: int("id").autoincrement().primaryKey(), userId: int("userId").notNull(), type: mysqlEnum("type", ["credit", "panel_purchase", "key_purchase", "voucher_redemption", "referral_reward"]).notNull(), amount: decimal("amount", { precision: 12, scale: 2 }).notNull(), description: varchar("description", { length: 255 }).notNull(), reference: varchar("reference", { length: 96 }), createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const vouchers = mysqlTable("vouchers", {
  id: int("id").autoincrement().primaryKey(), code: varchar("code", { length: 64 }).notNull().unique(), amount: decimal("amount", { precision: 12, scale: 2 }).notNull(), redeemedBy: int("redeemedBy"), redeemedAt: timestamp("redeemedAt"), createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const panelPlans = mysqlTable("panelPlans", {
  id: int("id").autoincrement().primaryKey(), name: varchar("name", { length: 120 }).notNull(), tier: varchar("tier", { length: 80 }).notNull(), description: text("description").notNull(), priceSd: decimal("priceSd", { precision: 12, scale: 2 }).notNull(), specs: text("specs").notNull(), active: boolean("active").default(true).notNull(),
});

export const orders = mysqlTable("orders", {
  id: int("id").autoincrement().primaryKey(), orderId: varchar("orderId", { length: 32 }).notNull().unique(), userId: int("userId").notNull(), planId: int("planId").notNull(), status: mysqlEnum("status", ["pending", "approved", "provisioned", "rejected"]).default("pending").notNull(), amountSd: decimal("amountSd", { precision: 12, scale: 2 }).notNull(), createdAt: timestamp("createdAt").defaultNow().notNull(), updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export const supportTickets = mysqlTable("supportTickets", {
  id: int("id").autoincrement().primaryKey(), userId: int("userId").notNull(), category: varchar("category", { length: 80 }).notNull(), botName: varchar("botName", { length: 120 }), phoneNumber: varchar("phoneNumber", { length: 32 }), subject: varchar("subject", { length: 180 }).notNull(), description: text("description").notNull(), screenshotUrl: text("screenshotUrl"), status: mysqlEnum("status", ["open", "in_progress", "resolved", "closed"]).default("open").notNull(), createdAt: timestamp("createdAt").defaultNow().notNull(), updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export const ticketMessages = mysqlTable("ticketMessages", {
  id: int("id").autoincrement().primaryKey(), ticketId: int("ticketId").notNull(), authorId: int("authorId").notNull(), message: text("message").notNull(), createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const referrals = mysqlTable("referrals", {
  id: int("id").autoincrement().primaryKey(), referrerId: int("referrerId").notNull(), referredUserId: int("referredUserId").notNull().unique(), rewardSd: decimal("rewardSd", { precision: 12, scale: 2 }).default("5.00").notNull(), status: mysqlEnum("status", ["pending", "rewarded"]).default("pending").notNull(), createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const botHealth = mysqlTable("botHealth", {
  id: int("id").autoincrement().primaryKey(), pairingId: int("pairingId").notNull().unique(), connectionStatus: mysqlEnum("connectionStatus", ["connected", "degraded", "offline"]).default("connected").notNull(), lastHeartbeat: timestamp("lastHeartbeat"), uptimeSeconds: int("uptimeSeconds").default(0).notNull(), cpuPercent: decimal("cpuPercent", { precision: 5, scale: 2 }).default("0.00").notNull(), ramMb: int("ramMb").default(0).notNull(), restartCount: int("restartCount").default(0).notNull(), lastError: text("lastError"),
});

export const notifications = mysqlTable("notifications", {
  id: int("id").autoincrement().primaryKey(), userId: int("userId").notNull(), title: varchar("title", { length: 180 }).notNull(), body: text("body").notNull(), read: boolean("read").default(false).notNull(), createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const docs = mysqlTable("docs", {
  id: int("id").autoincrement().primaryKey(), slug: varchar("slug", { length: 120 }).notNull().unique(), title: varchar("title", { length: 180 }).notNull(), category: varchar("category", { length: 80 }).notNull(), excerpt: text("excerpt").notNull(), content: text("content").notNull(), updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;
