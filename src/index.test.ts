import { describe, expect, test } from "bun:test";
import {
  buildSigilUrl,
  createConnectRequest,
  createEnvelope,
  createTransferRequest,
  hashSignedRequestPayload,
  isAllowedCallbackUrl,
  signEnvelope,
} from "./index";

describe("@sigil-oss/connect", () => {
  test("builds a Sigil URL with an envelope payload", () => {
    const request = createTransferRequest({
      type: "transfer",
      dapp: { name: "Demo", origin: "https://demo.app" },
      to: "UVYAOYTNYCRBVFBHNFIJUEOUEPEDIDUWWEAXKFSJEBJVASCQEROJOVOEEATL",
      amount: "1000",
    });

    const url = buildSigilUrl(
      createEnvelope(request, { callback: "https://demo.app/callback" }),
      { includeLegacyCallbackParam: true },
    );

    expect(url.startsWith("sigil://v1/request?d=")).toBe(true);
    expect(url.includes("&cb=https%3A%2F%2Fdemo.app%2Fcallback")).toBe(true);
  });

  test("allows only https and localhost http callbacks", () => {
    expect(isAllowedCallbackUrl("https://demo.app/cb")).toBe(true);
    expect(isAllowedCallbackUrl("http://localhost:3000/cb")).toBe(true);
    expect(isAllowedCallbackUrl("http://127.0.0.1:3000/cb")).toBe(true);
    expect(isAllowedCallbackUrl("http://demo.app/cb")).toBe(false);
  });

  test("signs an envelope with ES256 proof metadata", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

    const envelope = createEnvelope(
      createConnectRequest({
        type: "connect",
        dapp: { name: "Demo", origin: "https://demo.app" },
        permissions: ["transfer"],
      }),
      { callback: "https://demo.app/callback" },
    );

    const signed = await signEnvelope(envelope, {
      issuer: "demo.app",
      privateJwk,
      publicJwk,
      includePublicJwk: true,
    });

    expect(signed.proof?.algorithm).toBe("ES256");
    expect(signed.proof?.issuer).toBe("demo.app");
    expect(signed.proof?.signature.length).toBeGreaterThan(16);
    expect(signed.proof?.payload_hash).toBe(await hashSignedRequestPayload(envelope));
  });
});
