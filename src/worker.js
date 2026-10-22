// =====================================================================
// Cloudflare Worker: sigirsu-notary
//
// Firma transacciones del contrato SigirsuNotary en Polygon,
// autenticando llamadas desde SIGIRSU/portalgg con un token HMAC
// corto (mismo formato que sigirsu/autologin.php).
//
// Rutas:
//   POST /sign    -> envia una tx registrar(entidad, entidadId, hash)
//                    y devuelve { ok, txid, bloque, timestamp }.
//   POST /verify  -> lee un TXID de Polygon y confronta su hash on-chain
//                    con el hash esperado. Devuelve { ok, ... }.
//
// Secrets (en Cloudflare Dashboard):
//   PRIVATE_KEY       (clave privada hex de la wallet SIGIRSU)
//   RPC_URL           (Alchemy u otro provider Polygon mainnet)
//   WORKER_SECRET     (HMAC-SHA256 compartido con el .env de SIGIRSU)
//   CONTRACT_ADDRESS  (0xF4Ad...534a)
//
// Documentacion asociada:
//   ../sigirsu/docs/blockchain_notary/WORKER.md
//   ../sigirsu/docs/blockchain_notary/API.md
//   ../sigirsu/docs/blockchain_notary/SEGURIDAD.md
// =====================================================================

import { JsonRpcProvider, Wallet, Contract, Interface } from "ethers";
import abi from "./abi.json";

const TOKEN_WINDOW_SECONDS = 60;

export default {
  async fetch(request, env) {
    try {
      if (request.method !== "POST") {
        return json({ ok: false, error: "method_not_allowed" }, 405);
      }

      const token = request.headers.get("X-SIGIRSU-TOKEN") || "";
      const tokenCheck = await verifyToken(token, env.WORKER_SECRET);
      if (!tokenCheck.ok) {
        return json({ ok: false, error: tokenCheck.error }, 401);
      }

      const url = new URL(request.url);
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "json_invalido" }, 400);
      }

      if (url.pathname === "/sign")   return await handleSign(body, env);
      if (url.pathname === "/verify") return await handleVerify(body, env);
      return json({ ok: false, error: "not_found" }, 404);
    } catch (e) {
      return json({ ok: false, error: "internal", detalle: String(e && e.message || e) }, 500);
    }
  },
};

// --- /sign ---------------------------------------------------------------

async function handleSign({ entidad, entidadId, hash }, env) {
  if (entidad !== "CDF" && entidad !== "CDFD") {
    return json({ ok: false, error: "entidad_invalida" }, 400);
  }
  if (!Number.isInteger(entidadId) || entidadId < 0) {
    return json({ ok: false, error: "entidadId_invalida" }, 400);
  }
  if (typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)) {
    return json({ ok: false, error: "hash_invalido" }, 400);
  }

  const provider = new JsonRpcProvider(env.RPC_URL);
  const wallet   = new Wallet(env.PRIVATE_KEY, provider);
  const contract = new Contract(env.CONTRACT_ADDRESS, abi, wallet);

  const tx = await contract.registrar(entidad, BigInt(entidadId), hash);
  const receipt = await tx.wait(1);
  const block = await provider.getBlock(receipt.blockNumber);

  return json({
    ok: true,
    txid: receipt.hash,
    bloque: receipt.blockNumber,
    timestamp: Number(block.timestamp),
  });
}

// --- /verify -------------------------------------------------------------

async function handleVerify({ txid, hash_esperado }, env) {
  if (typeof txid !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(txid)) {
    return json({ ok: false, error: "txid_invalido" }, 400);
  }
  if (typeof hash_esperado !== "string" || !/^[0-9a-f]{64}$/.test(hash_esperado)) {
    return json({ ok: false, error: "hash_invalido" }, 400);
  }

  const provider = new JsonRpcProvider(env.RPC_URL);
  const receipt = await provider.getTransactionReceipt(txid);
  if (!receipt) {
    return json({ ok: false, error: "txid_no_encontrado" }, 404);
  }

  const iface = new Interface(abi);
  for (const log of receipt.logs) {
    try {
      // Solo decodificar logs cuyo address sea el contrato esperado.
      if (log.address && log.address.toLowerCase() !== env.CONTRACT_ADDRESS.toLowerCase()) {
        continue;
      }
      const parsed = iface.parseLog(log);
      if (parsed && parsed.name === "Registro") {
        const hashOnchain = String(parsed.args.hash);
        const bloque = Number(receipt.blockNumber);
        const timestamp = String(parsed.args.timestamp);
        return json({
          ok: hashOnchain === hash_esperado,
          entidad: String(parsed.args.entidad),
          entidadId: parsed.args.entidadId.toString(),
          hash_onchain: hashOnchain,
          bloque,
          timestamp,
        });
      }
    } catch { /* log de otro contrato o evento, ignorar */ }
  }
  return json({ ok: false, error: "evento_no_encontrado" }, 404);
}

// --- Autenticacion por token HMAC compartido con PHP ---------------------
// Formato: "<payload_b64url>.<sig_b64url>"
//   payload = JSON (al menos { ts: unix, nonce: hex, action: "sign"|"verify", ... })
//   sig     = base64url(hmac_sha256(payload_b64url, WORKER_SECRET))

async function verifyToken(token, secret) {
  if (!secret) return { ok: false, error: "server_sin_secret" };
  const dot = token.indexOf(".");
  if (dot < 1 || dot === token.length - 1) {
    return { ok: false, error: "token_malformado" };
  }
  const payloadB64 = token.slice(0, dot);
  const sigB64     = token.slice(dot + 1);

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign", "verify"]
  );

  let sigBytes;
  try { sigBytes = base64urlDecode(sigB64); }
  catch { return { ok: false, error: "token_firma_invalida" }; }

  const ok = await crypto.subtle.verify("HMAC", key, sigBytes, enc.encode(payloadB64));
  if (!ok) return { ok: false, error: "token_firma_invalida" };

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadB64)));
  } catch {
    return { ok: false, error: "token_payload_invalido" };
  }

  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(payload.ts) || Math.abs(now - payload.ts) > TOKEN_WINDOW_SECONDS) {
    return { ok: false, error: "token_fuera_de_ventana" };
  }
  return { ok: true, payload };
}

// --- Helpers -------------------------------------------------------------

function base64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
      "cache-control": "no-store",
    },
  });
}
