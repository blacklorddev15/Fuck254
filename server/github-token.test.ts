import { describe, expect, it } from "vitest";

describe("GitHub push credential", () => {
  it("authenticates with GitHub without exposing the token", async () => {
    const token = process.env.GITHUB_TOKEN;
    expect(token).toBeTruthy();

    const response = await fetch("https://api.github.com/user", {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });

    expect(response.ok).toBe(true);
    const user = (await response.json()) as { login?: string };
    expect(user.login).toBe("blacklorddev15");
  }, 15_000);
});
