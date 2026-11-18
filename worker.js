
const corsOrigin = "https://techyreward.github.io";

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");
    const headers = {
      "Access-Control-Allow-Origin": corsOrigin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Content-Type": "application/json"
    };
    
    if (origin !== corsOrigin) {
      return new Response("Forbidden", { status: 403 });
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { headers });
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed", {
        status: 405, headers
      });
    }

    try {
      const body = await request.json();
      const initData = body.initData;

      if (typeof initData !== "string" || initData.length > 10000) {
        throw new Error("Invalid login data");
      }

      const params = new URLSearchParams(initData);
      const receivedHash = params.get("hash");
      const authDate = Number(params.get("auth_date"));
      const userText = params.get("user");

      if (!receivedHash || !userText || !authDate) {
        throw new Error("Missing Telegram data");
      }

      const now = Math.floor(Date.now() / 1000);
      if (authDate > now + 60 || now - authDate > 86400) {
        throw new Error("Login data expired");
      }

      params.delete("hash");

      const checkString = [...params.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => `${k}=${v}`)
        .join("\n");

      const encoder = new TextEncoder();

      async function hmac(keyBytes, message) {
        const key = await crypto.subtle.importKey(
          "raw", keyBytes,
          { name: "HMAC", hash: "SHA-256" },
          false, ["sign"]
        );
        return new Uint8Array(
          await crypto.subtle.sign("HMAC", key, encoder.encode(message))
        );
      }

      const secretKey = await hmac(
        encoder.encode("WebAppData"),
        env.TELEGRAM_BOT_TOKEN
      );

      const calculatedHash = [...await hmac(secretKey, checkString)]
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");

      if (
        !/^[a-f0-9]{64}$/i.test(receivedHash) ||
        calculatedHash.length !== receivedHash.length ||
        ![...calculatedHash].every(
          (c, i) => c === receivedHash.toLowerCase()[i]
        )
      ) {
        throw new Error("Telegram verification failed");
      }

      const user = JSON.parse(userText);
      if (!user.id) throw new Error("Invalid Telegram user");

      const service = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT_JSON);

      if (
        service.project_id !== env.FIREBASE_PROJECT_ID ||
        !service.client_email ||
        !service.private_key
      ) {
        throw new Error("Firebase configuration error");
      }

      function base64url(value) {
        const bytes = typeof value === "string"
          ? encoder.encode(value)
          : value;
        let binary = "";
        for (const b of bytes) binary += String.fromCharCode(b);
        return btoa(binary)
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=+$/, "");
      }

      const pem = service.private_key
        .replace(/-----BEGIN PRIVATE KEY-----/g, "")
        .replace(/-----END PRIVATE KEY-----/g, "")
        .replace(/\s/g, "");

      const keyBytes = Uint8Array.from(
        atob(pem), c => c.charCodeAt(0)
      );

      const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        keyBytes,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["sign"]
      );

      const issuedAt = Math.floor(Date.now() / 1000);

      const jwtHeader = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
      const jwtPayload = base64url(JSON.stringify({
        iss: service.client_email,
        sub: service.client_email,
        aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
        iat: issuedAt,
        exp: issuedAt + 3600,
        uid: String(user.id)
      }));

      const unsigned = `${jwtHeader}.${jwtPayload}`;

      const signature = new Uint8Array(
        await crypto.subtle.sign(
          "RSASSA-PKCS1-v1_5",
          privateKey,
          encoder.encode(unsigned)
        )
      );

      const customToken = `${unsigned}.${base64url(signature)}`;

      return new Response(JSON.stringify({
        success: true,
        customToken
      }), { status: 200, headers });

      } catch (error) {
  console.error("Techy Auth Error:", error);

  return new Response(JSON.stringify({
    success: false,
    error: "Login verification failed",
    detail: String(error.message || "Unknown error")
  }), { status: 401, headers });
      
    }
  }
};
