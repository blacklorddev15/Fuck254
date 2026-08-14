import { desc, eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import { ENV } from "./_core/env";
import { InsertUser, users, bots, pairings, telegramKeys, walletTransactions, panelPlans, orders, supportTickets, ticketMessages, botHealth, notifications, docs } from "../drizzle/schema";

let _db: ReturnType<typeof drizzle> | null = null;
export async function getDb() { if (!_db && process.env.DATABASE_URL) { try { _db = drizzle(process.env.DATABASE_URL); } catch (error) { console.warn("[Database] Failed to connect:", error); } } return _db; }

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) throw new Error("User openId is required for upsert");
  const db = await getDb(); if (!db) return;
  const values: InsertUser = { openId: user.openId, name: user.name ?? null, email: user.email ?? null, loginMethod: user.loginMethod ?? null, lastSignedIn: user.lastSignedIn ?? new Date() };
  const updateSet: Record<string, unknown> = { name: values.name, email: values.email, loginMethod: values.loginMethod, lastSignedIn: values.lastSignedIn };
  if (user.role) { values.role = user.role; updateSet.role = user.role; }
  if (user.openId === ENV.ownerOpenId) { values.role = "admin"; updateSet.role = "admin"; }
  await db.insert(users).values(values).onDuplicateKeyUpdate({ set: updateSet });
}

export async function getUserByOpenId(openId: string) { const db = await getDb(); if (!db) return undefined; const rows = await db.select().from(users).where(eq(users.openId, openId)).limit(1); return rows[0]; }
export async function getBots() { const db = await getDb(); if (!db) return []; return db.select().from(bots).orderBy(bots.id); }
export async function getPlans() { const db = await getDb(); if (!db) return []; return db.select().from(panelPlans).where(eq(panelPlans.active, true)).orderBy(panelPlans.id); }
export async function getDocs(query?: string) { const db = await getDb(); if (!db) return []; const rows = await db.select().from(docs).orderBy(desc(docs.updatedAt)); return query ? rows.filter((d) => `${d.title} ${d.category} ${d.excerpt}`.toLowerCase().includes(query.toLowerCase())) : rows; }
export async function getUserPairings(userId: number) { const db = await getDb(); if (!db) return []; return db.select().from(pairings).where(eq(pairings.userId, userId)).orderBy(desc(pairings.createdAt)); }
export async function getUserKeys(userId: number) { const db = await getDb(); if (!db) return []; return db.select().from(telegramKeys).where(eq(telegramKeys.userId, userId)).orderBy(desc(telegramKeys.createdAt)); }
export async function getUserTransactions(userId: number) { const db = await getDb(); if (!db) return []; return db.select().from(walletTransactions).where(eq(walletTransactions.userId, userId)).orderBy(desc(walletTransactions.createdAt)); }
export async function getUserOrders(userId: number) { const db = await getDb(); if (!db) return []; return db.select().from(orders).where(eq(orders.userId, userId)).orderBy(desc(orders.createdAt)); }
export async function getUserTickets(userId: number) { const db = await getDb(); if (!db) return []; return db.select().from(supportTickets).where(eq(supportTickets.userId, userId)).orderBy(desc(supportTickets.createdAt)); }
export async function getUserNotifications(userId: number) { const db = await getDb(); if (!db) return []; return db.select().from(notifications).where(eq(notifications.userId, userId)).orderBy(desc(notifications.createdAt)); }
export async function getHealthForPairing(pairingId: number) { const db = await getDb(); if (!db) return undefined; const rows = await db.select().from(botHealth).where(eq(botHealth.pairingId, pairingId)).limit(1); return rows[0]; }
export async function getTicketMessages(ticketId: number) { const db = await getDb(); if (!db) return []; return db.select().from(ticketMessages).where(eq(ticketMessages.ticketId, ticketId)).orderBy(ticketMessages.createdAt); }
export async function getUserTicket(userId: number, ticketId: number) { const db = await getDb(); if (!db) return undefined; const rows = await db.select().from(supportTickets).where(eq(supportTickets.userId, userId)).limit(1); return rows.find((ticket) => ticket.id === ticketId); }

