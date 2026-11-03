# shardsign

PoC de una wallet EVM headless cuya clave ECDSA nunca existe completa. La clave se reparte 2-de-3 con TSS entre el usuario (browser, WASM) y dos signers que guardan su share en OpenBao. Firma transacciones EVM normales (legacy, EIP-155, `gasPrice=0`) sobre una cadena local (Anvil). No usa ERC-4337.

- Especificación: https://claude.ai/artifact/W6vweYBNtTq9YjZXk36z5i (todavía habla de UserOps, GG20 y Besu; abajo están los desvíos)
- Plan de 5 días, gates y resultados: [PLAN.md](PLAN.md)

## Estado

| Día | Alcance | Estado |
|---|---|---|
| 1 | `pkg/tss` (DKG, firma, reshare), parte `user` en WASM, cadena local con TestToken | ✅ Hecho (2026-11-03) |
| 2 | `signer` con OpenBao, validación de tx, `coordinator`, CLI de la parte `user` | ⏳ Pendiente |
| 3 | Firma end-to-end con `eth_sendRawTransaction`, fallback a signer-b, `otp-service` | ⏳ Pendiente |
| 4 | Front (login, crear wallet, enviar con PIN), reshare y `/recover` | ⏳ Pendiente |
| 5 | Modo `operators`, `app-wallet.ts`, script de aceptación | ⏳ Pendiente |

### Hecho (día 1)

- [x] DKG, firma y reshare 2-de-3 en Go con tss-lib v2.0.2. Después del reshare, la dirección no cambia y la share vieja ya no combina con las nuevas
- [x] La parte `user` corre en WASM en Chrome. Hace DKG contra dos partes Go, y las firmas con signer-a y con signer-b recuperan la dirección de la wallet
- [x] Generador propio de preparams (`tss.FindSafePrime`), porque `keygen.GeneratePreParams` de tss-lib se cuelga en WASM. En el browser se reparte en Web Workers
- [x] Cadena local Anvil (chainId 7773, gas 0) con TestToken. Una cuenta sin ETH mina una transferencia legacy con `gasPrice=0`

| Medición | Go nativo | Browser (WASM) | Objetivo |
|---|---|---|---|
| Preparams por parte | 4–7 s | 49–85 s | durante el login |
| DKG | 3,0 s | 23 s | < 5–10 s ❌ |
| Firma | 0,18 s | 1,9 s | < 3 s ✅ |
| WASM | — | 20 MB (3,6 MB con brotli) | 8–15 MB |

### Pendientes

**Implementación** (días 2 a 5, criterios de aceptación de [PLAN.md](PLAN.md)):
- [ ] Crear wallet desde el browser; la dirección coincide entre front, signer-a y signer-b
- [ ] Una transferencia de TestToken firmada en modo usuario se mina
- [ ] Con signer-a apagado, la misma transferencia pasa por signer-b
- [ ] Un destino fuera de `allowed_to` devuelve `403 policy_denied` y ningún signer descifra su share (audit)
- [ ] El modo `operators` firma sin la tercera share solo si `operators.enabled=true`
- [ ] Reshare a un browser nuevo mantiene la dirección y la share vieja no produce firmas válidas
- [ ] Apagar y levantar los dos OpenBao (con unseal) no pierde ninguna wallet
- [ ] Ningún log contiene teléfono, JWT ni bytes de share

**Decisiones abiertas:**
- [ ] Aceptar un DKG en browser < 30 s con indicador de progreso, en lugar de < 5–10 s. Corre una vez por wallet
- [ ] Preparams del browser: generarlos una vez por dispositivo y guardarlos cifrados con el PIN (día 4)
- [ ] Verificar el día 2 que los contenedores llegan a Anvil por `host.docker.internal:8545` (Anvil escucha solo en 127.0.0.1)

**Documentación:**
- [ ] Alinear la spec con lo construido: tx EVM normales en vez de UserOps, GG18 en vez de GG20, Anvil en vez de Besu
- [ ] Actualizar o retirar el plan de 6 semanas en Claude Docs; el plan vigente es `PLAN.md`

## Desvíos respecto de la spec

- **Tx EVM normales, sin ERC-4337.** La wallet es una EOA cuya dirección se deriva de la pubkey TSS.
- **GG18, no GG20.** Es lo que implementa tss-lib v2.0.2.
- **Anvil, no Besu.** Corre nativo y sin contenedor. El código usa solo RPC estándar `eth_*`, así que volver a Besu es cambiar la URL.

## Cómo correrlo

Requisitos: Go 1.27, Foundry (`anvil`, `forge`, `cast`), `jq`, `brotli`, Chrome.

```
make test      # tests de pkg/tss (la primera corrida genera preparams, ~10 s)
make chain     # Anvil en primer plano; el estado queda en .anvil/
make smoke     # con make chain corriendo: despliega TestToken y mina una tx con gasPrice=0
make devpeer   # signers del spike + página; abrir http://127.0.0.1:8090/?auto (&cache reusa preparams)
```

## Estructura

```
pkg/tss/      TSS (wrapper de tss-lib): Session/Envelope, preparams, dirección y firma Ethereum
wasm/         pkg/tss compilado a WebAssembly (globalThis.shardsign)
spike/        código descartable del día 1: devpeer (2 signers + página), ppbench
contracts/    Foundry: TestToken (ERC-20 con mint abierto)
infra/        dev-keys.env (clave pública de Anvil, solo local)
scripts/      smoke.sh
```

Más adelante: `signer/`, `coordinator/`, `otp-service/`, `web/` (ver [PLAN.md](PLAN.md)).
