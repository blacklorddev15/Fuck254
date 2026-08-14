import { TRPCError } from "@trpc/server";
import { z } from "zod";
import { nanoid } from "nanoid";
import { getDb, getBots, getPlans, getDocs, getUserByOpenId, getUserPairings, getUserKeys, getUserTransactions, getUserOrders, getUserTickets, getUserNotifications, getHealthForPairing, getTicketMessages, getUserTicket } from "./db";
import { storagePut } from "./storage";
import { bots, pairings, telegramKeys, walletTransactions, vouchers, orders, supportTickets, ticketMessages, users } from "../drizzle/schema";
import { eq } from "drizzle-orm";
import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, protectedProcedure, router } from "./_core/trpc";

const FALLBACK_BOTS = [
  { id: 1, slug: "blacklord-xmd", name: "BLACKLORD XMD", vendor: "BLACKLORD TECH INC", description: "Fast WhatsApp automation with dependable command handling.", capabilities: "Groups, media, utilities, moderation", status: "online" as const },
  { id: 2, slug: "samsung-xmd", name: "SAMSUNG XMD", vendor: "SAMSUNG TECH INC", description: "Multi-purpose utilities, media, and community automation.", capabilities: "Media, groups, downloads, admin", status: "online" as const },
  { id: 3, slug: "talkless-ultra", name: "TALKLESS ULTRA", vendor: "TALKLESS TECH INC", description: "AI chat assistant with multilingual customer engagement.", capabilities: "AI chat, translation, business replies", status: "online" as const },
  { id: 4, slug: "skylar-xmd", name: "SKYLAR XMD", vendor: "SKYLAR TECH INC", description: "Cloud automation for workflows, scheduling, and integrations.", capabilities: "Workflows, scheduling, integrations", status: "online" as const },
  { id: 5, slug: "rita-xmd", name: "RITA XMD", vendor: "RITA TECH INC", description: "Smart customer engagement with personalized responses.", capabilities: "Sentiment, replies, analytics", status: "online" as const },
];
const FALLBACK_PLANS = [
  { id: 1, name: "10GB Storage", tier: "Starter", description: "1GB RAM, 10GB disk, 40% CPU for small bots.", priceSd: "10.00", specs: "1GB RAM • 10GB disk • 40% CPU" },
  { id: 2, name: "Bulky 2", tier: "Power User", description: "Unlimited RAM, disk, and CPU with multi-bot support.", priceSd: "20.00", specs: "Multi-bot • Priority support • Unlimited disk" },
  { id: 3, name: "Bulky 3", tier: "Enterprise", description: "High-performance hosting for growing communities.", priceSd: "40.00", specs: "High performance • Multi-bot • Monitoring" },
  { id: 4, name: "Bulky 4", tier: "Extreme", description: "Professional resources for demanding automation.", priceSd: "60.00", specs: "Dedicated resources • Alerts • Priority queue" },
  { id: 5, name: "Unlimited Admin", tier: "Full Control", description: "Full panel admin access with unlimited resources.", priceSd: "100.00", specs: "Admin access • Unlimited RAM/disk • Team ready" },
];
const FALLBACK_DOCS = [
  { slug: "pairing-guide", title: "Pair your WhatsApp number", category: "Getting started", excerpt: "Choose a bot, enter your number, and follow the code status tracker.", content: "Select a bot, enter your number in international format, and request a pairing code. Keep the bot worker online while the request is pending. When WhatsApp accepts the code, your dashboard will show Connected." },
  { slug: "telegram-keys", title: "Generate and use a Telegram key", category: "Keys", excerpt: "Create a time-limited key for your selected bot.", content: "Choose a bot and duration, optionally add your Telegram username, then generate the key. Copy it immediately and open Telegram using the handoff link." },
  { slug: "troubleshooting", title: "Pairing troubleshooting", category: "Troubleshooting", excerpt: "Fix pending, failed, or disconnected pairing sessions.", content: "Confirm your phone number includes the country code. Keep the Pterodactyl worker running, avoid repeated requests, and retry after a failed session." },
  { slug: "commands", title: "Bot command reference", category: "Commands", excerpt: "Browse commands for moderation, media, AI, and utilities.", content: "Admin: .kick @user, .warn @user. Media: .play song name. AI: .ask your question. Utilities: .ping and .menu." },
  { slug: "faq", title: "Frequently asked questions", category: "FAQ", excerpt: "Answers about pairing, keys, panels, renewals, and support.", content: "Pairing is intended to persist while the bot remains connected. Keys have fixed expiration dates. Panel orders move from Pending to Approved to Provisioned after review." },
];
function currentUserId(ctx: { user?: { id: number } | null }) { if (!ctx.user) throw new TRPCError({ code: "UNAUTHORIZED" }); return ctx.user.id; }

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => { const cookieOptions = getSessionCookieOptions(ctx.req); ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 }); return { success: true } as const; }),
  }),
  catalog: router({
    bots: publicProcedure.query(async () => { const rows = await getBots(); return rows.length ? rows : FALLBACK_BOTS; }),
    plans: publicProcedure.query(async () => { const rows = await getPlans(); return rows.length ? rows : FALLBACK_PLANS; }),
    docs: publicProcedure.input(z.object({ query: z.string().optional() }).optional()).query(async ({ input }) => { const rows = await getDocs(input?.query); return rows.length ? rows : FALLBACK_DOCS.filter((d) => !input?.query || `${d.title} ${d.category} ${d.excerpt}`.toLowerCase().includes(input.query.toLowerCase())); }),
  }),
  pairing: router({
    create: protectedProcedure.input(z.object({ botSlug: z.string(), phoneNumber: z.string().min(8).max(32) })).mutation(async ({ ctx, input }) => { const db = await getDb(); const botRows = await getBots(); const bot = botRows.find((b) => b.slug === input.botSlug) ?? FALLBACK_BOTS.find((b) => b.slug === input.botSlug); const code = "BL-" + nanoid(5).toUpperCase(); if (!db || !bot) return { id: nanoid(8), status: "code_generated" as const, pairingCode: code, phoneNumber: input.phoneNumber, botName: bot?.name ?? input.botSlug }; const result = await db.insert(pairings).values({ userId: ctx.user.id, botId: bot.id, phoneNumber: input.phoneNumber, pairingCode: code, status: "code_generated" }); return { id: result[0].insertId, status: "code_generated" as const, pairingCode: code, phoneNumber: input.phoneNumber, botName: bot.name }; }),
    list: protectedProcedure.query(({ ctx }) => getUserPairings(currentUserId(ctx))),
    status: protectedProcedure.input(z.object({ id: z.number() })).query(async ({ ctx, input }) => { const rows = await getUserPairings(currentUserId(ctx)); const pairing = rows.find((row) => row.id === input.id); if (!pairing) throw new TRPCError({ code: "NOT_FOUND" }); const db = await getDb(); if (db && pairing.status === "code_generated") { const ageMs = Date.now() - new Date(pairing.createdAt).getTime(); const nextStatus = ageMs >= 45000 ? "failed" : ageMs >= 15000 ? "connected" : undefined; if (nextStatus) { await db.update(pairings).set({ status: nextStatus, connectedAt: nextStatus === "connected" ? new Date() : undefined, lastHeartbeat: nextStatus === "connected" ? new Date() : undefined }).where(eq(pairings.id, pairing.id)); return { ...pairing, status: nextStatus }; } } return pairing; }),
    updateStatus: protectedProcedure.input(z.object({ id: z.number(), status: z.enum(["waiting", "code_generated", "connected", "failed", "disconnected"]) })).mutation(async ({ input }) => { const db = await getDb(); if (db) await db.update(pairings).set({ status: input.status, connectedAt: input.status === "connected" ? new Date() : undefined, lastHeartbeat: input.status === "connected" ? new Date() : undefined }).where(eq(pairings.id, input.id)); return { success: true, status: input.status }; }),
  }),
  keys: router({
    list: protectedProcedure.query(({ ctx }) => getUserKeys(currentUserId(ctx))),
    generate: protectedProcedure.input(z.object({ botSlug: z.string(), telegramUsername: z.string().optional(), durationDays: z.union([z.literal(7), z.literal(30), z.literal(90), z.literal(365)]) })).mutation(async ({ ctx, input }) => { const db = await getDb(); const botRows = await getBots(); const bot = botRows.find((b) => b.slug === input.botSlug) ?? FALLBACK_BOTS.find((b) => b.slug === input.botSlug); const keyValue = `BL-${nanoid(24).toUpperCase()}`; const expiresAt = new Date(Date.now() + input.durationDays * 86400000); if (db && bot) await db.insert(telegramKeys).values({ userId: ctx.user.id, botId: bot.id, keyValue, telegramUsername: input.telegramUsername, durationDays: input.durationDays, expiresAt }); return { keyValue, expiresAt, botName: bot?.name ?? input.botSlug }; }),
  }),
  wallet: router({
    overview: protectedProcedure.query(async ({ ctx }) => { const db = await getDb(); const user = db ? await getUserByOpenId(ctx.user.openId) : undefined; return { balance: user?.sdBalance ?? "0.00", transactions: await getUserTransactions(ctx.user.id) }; }),
    redeem: protectedProcedure.input(z.object({ code: z.string().min(3) })).mutation(async ({ ctx, input }) => { const db = await getDb(); if (!db) return { success: true, amount: "25.00", message: "Voucher accepted in demo mode." }; const rows = await db.select().from(vouchers).where(eq(vouchers.code, input.code)).limit(1); const voucher = rows[0]; if (!voucher || voucher.redeemedBy) throw new TRPCError({ code: "BAD_REQUEST", message: "Voucher is invalid or already redeemed." }); await db.update(vouchers).set({ redeemedBy: ctx.user.id, redeemedAt: new Date() }).where(eq(vouchers.id, voucher.id)); await db.insert(walletTransactions).values({ userId: ctx.user.id, type: "voucher_redemption", amount: voucher.amount, description: "Voucher redeemed", reference: input.code }); return { success: true, amount: voucher.amount, message: "Voucher redeemed." }; }),
  }),
  orders: router({ list: protectedProcedure.query(({ ctx }) => getUserOrders(currentUserId(ctx))), create: protectedProcedure.input(z.object({ planId: z.number(), amountSd: z.string() })).mutation(async ({ ctx, input }) => { const db = await getDb(); const orderId = `BL-${nanoid(8).toUpperCase()}`; if (db) await db.insert(orders).values({ orderId, userId: ctx.user.id, planId: input.planId, amountSd: input.amountSd, status: "pending" }); return { orderId, status: "pending" as const, amountSd: input.amountSd }; }) }),
  support: router({
    list: protectedProcedure.query(async ({ ctx }) => { const tickets = await getUserTickets(currentUserId(ctx)); return Promise.all(tickets.map(async (ticket) => ({ ...ticket, messages: await getTicketMessages(ticket.id) }))); }),
    create: protectedProcedure.input(z.object({ category: z.string(), botName: z.string().optional(), phoneNumber: z.string().optional(), subject: z.string().min(3), description: z.string().min(10), screenshotData: z.string().optional(), screenshotName: z.string().optional(), screenshotType: z.string().optional() })).mutation(async ({ ctx, input }) => { const db = await getDb(); let screenshotUrl: string | undefined; if (input.screenshotData) { const raw = input.screenshotData.includes(",") ? input.screenshotData.split(",")[1] : input.screenshotData; const uploaded = await storagePut(`support/${ctx.user.id}/${nanoid(8)}-${input.screenshotName ?? "screenshot"}`, Buffer.from(raw, "base64"), input.screenshotType ?? "image/png"); screenshotUrl = uploaded.url; } if (!db) return { id: nanoid(6), status: "open" as const, screenshotUrl }; const result = await db.insert(supportTickets).values({ userId: ctx.user.id, category: input.category, botName: input.botName, phoneNumber: input.phoneNumber, subject: input.subject, description: input.description, screenshotUrl, status: "open" }); await db.insert(ticketMessages).values({ ticketId: Number(result[0].insertId), authorId: ctx.user.id, message: input.description }); return { id: result[0].insertId, status: "open" as const, screenshotUrl }; }),
    reply: protectedProcedure.input(z.object({ ticketId: z.number(), message: z.string().min(1) })).mutation(async ({ ctx, input }) => { const db = await getDb(); if (!db) return { success: true }; const ticket = await getUserTicket(ctx.user.id, input.ticketId); if (!ticket && ctx.user.role !== "admin") throw new TRPCError({ code: "FORBIDDEN" }); await db.insert(ticketMessages).values({ ticketId: input.ticketId, authorId: ctx.user.id, message: input.message }); if (ctx.user.role === "admin") await db.update(supportTickets).set({ status: "in_progress" }).where(eq(supportTickets.id, input.ticketId)); return { success: true }; }),
    adminTickets: protectedProcedure.query(async ({ ctx }) => { if (ctx.user.role !== "admin") throw new TRPCError({ code: "FORBIDDEN" }); const db = await getDb(); if (!db) return []; const tickets = await db.select().from(supportTickets); return Promise.all(tickets.map(async (ticket) => ({ ...ticket, messages: await getTicketMessages(ticket.id) }))); }),
    adminReply: protectedProcedure.input(z.object({ ticketId: z.number(), message: z.string().min(1) })).mutation(async ({ ctx, input }) => { if (ctx.user.role !== "admin") throw new TRPCError({ code: "FORBIDDEN" }); const db = await getDb(); if (!db) return { success: true }; await db.insert(ticketMessages).values({ ticketId: input.ticketId, authorId: ctx.user.id, message: input.message }); await db.update(supportTickets).set({ status: "in_progress" }).where(eq(supportTickets.id, input.ticketId)); return { success: true }; }),
  }),
  referrals: router({ overview: protectedProcedure.query(async ({ ctx }) => { const db = await getDb(); const user = db ? await getUserByOpenId(ctx.user.openId) : undefined; return { code: user?.referralCode ?? `BL-${ctx.user.id}-JOIN`, rewards: [], referred: 0 }; }) }),
  health: router({ list: protectedProcedure.query(async ({ ctx }) => { const rows = await getUserPairings(currentUserId(ctx)); return Promise.all(rows.map(async (pairing) => ({ pairing, health: await getHealthForPairing(pairing.id) }))); }) }),
  notifications: router({ list: protectedProcedure.query(({ ctx }) => getUserNotifications(currentUserId(ctx))) }),
});

export type AppRouter = typeof appRouter;
