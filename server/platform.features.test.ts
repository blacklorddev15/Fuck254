import { describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

type User = NonNullable<TrpcContext["user"]>;
const user: User = { id: 42, openId: "feature-user", name: "Feature User", email: "feature@example.com", loginMethod: "test", role: "user", createdAt: new Date(), updatedAt: new Date(), lastSignedIn: new Date() };
const ctx = { user, req: { protocol: "https", headers: {} } as TrpcContext["req"], res: {} as TrpcContext["res"] } as TrpcContext;

describe("Fuck254 platform feature contracts", () => {
  it("returns the five public bot profiles and searchable docs fallback", async () => {
    const caller = appRouter.createCaller({ ...ctx, user: null });
    const bots = await caller.catalog.bots();
    const docs = await caller.catalog.docs({ query: "pairing" });
    expect(bots).toHaveLength(5);
    expect(docs.length).toBeGreaterThan(0);
    expect(docs.some((doc) => `${doc.title} ${doc.excerpt}`.toLowerCase().includes("pair"))).toBe(true);
  });

  it("creates a pairing code and exposes the supported status contract", async () => {
    const caller = appRouter.createCaller(ctx);
    const pairing = await caller.pairing.create({ botSlug: "blacklord-xmd", phoneNumber: "254712345678" });
    expect(pairing.status).toBe("code_generated");
    expect(pairing.pairingCode).toMatch(/^BL-/);
  });

  it("generates a time-limited Telegram key for an allowed duration", async () => {
    const caller = appRouter.createCaller(ctx);
    const key = await caller.keys.generate({ botSlug: "blacklord-xmd", durationDays: 90 });
    expect(key.keyValue).toMatch(/^BL-/);
    expect(key.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it("supports wallet redemption, order creation, and ticket creation contracts", async () => {
    const caller = appRouter.createCaller(ctx);
    await expect(caller.wallet.redeem({ code: "DEMO-VOUCHER" })).rejects.toThrow("Voucher is invalid or already redeemed.");
    const order = await caller.orders.create({ planId: 1, amountSd: "10.00" });
    const ticket = await caller.support.create({ category: "Pairing", botName: "BLACKLORD XMD", subject: "Pairing failed", description: "The pairing code expired before WhatsApp accepted it." });
    expect(order.status).toBe("pending");
    expect(ticket.status).toBe("open");
  });

  it("rejects invalid key durations at the typed procedure boundary", async () => {
    const caller = appRouter.createCaller(ctx);
    await expect(caller.keys.generate({ botSlug: "blacklord-xmd", durationDays: 14 as never })).rejects.toThrow();
  });
});
