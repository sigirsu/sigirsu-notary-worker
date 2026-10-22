# sigirsu-notary-worker

Cloudflare Worker que custodia la clave privada de la wallet SIGIRSU y firma
transacciones del contrato `SigirsuNotary` en Polygon.

- **Contrato**: `0xF4Ad4c2Ecd4B9c32E779aF55fB38a233EA40534a`
- **Red**: Polygon Mainnet (Chain ID 137)
- **Polygonscan**: https://polygonscan.com/address/0xF4Ad4c2Ecd4B9c32E779aF55fB38a233EA40534a
- **Sourcify**: https://repo.sourcify.dev/137/0xF4Ad4c2Ecd4B9c32E779aF55fB38a233EA40534a

## Documentación

Toda la operación, seguridad y procedimientos del Worker están en el repo
principal de SIGIRSU, en
[`sigirsu/docs/blockchain_notary/WORKER.md`](../sigirsu/docs/blockchain_notary/WORKER.md).
Léelo antes de deployar o rotar secrets.

## Despliegue sin consola

1. Crear repo en github.com con estos 4 archivos:
   `package.json`, `wrangler.toml`, `src/worker.js`, `src/abi.json`.
2. Cloudflare Dashboard → Workers & Pages → **Create → Continue with GitHub**
   → seleccionar el repo. Cloudflare detecta `package.json`, corre
   `npm install` y deploya.
3. Dashboard del Worker → **Settings → Variables and Secrets** → cargar
   4 secrets: `PRIVATE_KEY`, `RPC_URL`, `WORKER_SECRET`, `CONTRACT_ADDRESS`.
4. Dashboard del Worker → **Settings → Rate limiting rules** → activar
   un límite básico (sugerido: 20 req/min por IP).
5. Copiar la URL asignada (p.ej. `https://sigirsu-notary.xxx.workers.dev`)
   y pegarla como `BLOCKCHAIN_WORKER_URL` en el `.env` del server SIGIRSU
   y de portalgg.

## Endpoints

- `POST /sign` — Firma y envía `registrar(entidad, entidadId, hash)`.
- `POST /verify` — Lee un TXID y confronta hash on-chain con hash esperado.

Request/response completos en
[`sigirsu/docs/blockchain_notary/API.md`](../sigirsu/docs/blockchain_notary/API.md).

## Autenticación

Header `X-SIGIRSU-TOKEN` con un token HMAC-SHA256 corto en formato
`<payload_b64url>.<sig_b64url>`, mismo formato que
[`sigirsu/autologin.php`](../sigirsu/autologin.php). Firmado del lado PHP con
`BLOCKCHAIN_WORKER_SECRET` (que debe coincidir con el `WORKER_SECRET` del
Worker). Ventana de validez: ±60s.

## Seguridad

- La `PRIVATE_KEY` existe solo en Cloudflare Workers Secrets (cifrada at rest).
- Nunca commitear secrets.
- Rotación de secretos documentada en
  [`sigirsu/docs/blockchain_notary/OPERACION.md`](../sigirsu/docs/blockchain_notary/OPERACION.md).

## Costos

- Workers plan gratuito: 100.000 requests/día (más que suficiente).
- Gas por sellado: ~0.001–0.01 USD en POL. Con 37 POL alcanzan miles de
  sellados.
