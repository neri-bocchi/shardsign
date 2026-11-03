# Plan de implementación — PoC Wallet TSS + OpenBao (5 días)

Basado en la [especificación del PoC](https://claude.ai/artifact/W6vweYBNtTq9YjZXk36z5i). Reemplaza al plan de 6 semanas.

En 5 días entra la tesis del PoC: una wallet nace por DKG entre el browser y dos signers, firma una transacción EVM normal que se mina en una cadena local (Anvil), se recupera por reshare con la misma dirección, y cada acceso a una share queda en el audit de OpenBao. Para llegar, se recorta todo lo que no prueba eso. Cada día cierra con un gate verificable; si un gate falla, se activa su plan B en vez de correr el resto.

## Resultado del día 1 (2026-11-03)

Los dos gates pasan: el browser hace DKG y firma contra dos partes Go, y una cuenta sin ETH mina una tx legacy con `gasPrice=0`.

| Medición | Go nativo (3 partes en proceso) | Browser (Chrome, WASM) contra 2 partes Go | Objetivo de la spec |
|---|---|---|---|
| Preparams por parte | 4–7 s (4 workers) | 49–85 s (7 Web Workers) | "durante el login" |
| DKG 2-de-3 | 3,0 s | 22,7 s | < 5 s / < 10 s |
| Firma 2-de-3 | 0,18 s | 1,9 s | < 3 s |
| Reshare | 3,2 s | sin medir (día 4) | — |
| Tamaño del WASM | — | 20 MB, 3,6 MB con brotli; carga 130 ms en local | 8–15 MB |

Hallazgos:
- **tss-lib v2.0.2 implementa GG18** (su README cita Gennaro–Goldfeder CCS 2018), no GG20. La spec debe decirlo.
- **`keygen.GeneratePreParams` se cuelga en WASM.** Su búsqueda concurrente de primos seguros deja una goroutine bloqueada en un canal; en WASM (sin preemption) pasa siempre. Se reemplazó por `tss.GeneratePreParams` / `tss.FindSafePrime` en `pkg/tss/preparams.go`, que además permite repartir la búsqueda en Web Workers. En nativo también es más rápido (4–7 s contra 20–40 s).
- **Los enteros grandes no sobreviven `JSON.parse`.** Shares y preparams cruzan la frontera JS↔WASM como texto JSON opaco (`keyJSON`, `preParamsJSON`).
- **El DKG en el browser (23 s) no cumple el objetivo.** La firma sí. Como el DKG corre una vez por wallet, se propone aceptar < 30 s con indicador de progreso, y anotar como optimización posterior mover las pruebas pesadas de la parte `user` a workers.
- **Preparams en el browser tardan ~1 min.** Se generan una vez por dispositivo y se guardan cifrados con el PIN (día 4), no en cada wallet.
- **Cadena: Anvil en lugar de Besu** (decidido después del gate; Besu queda fuera del PoC). Anvil corre nativo, sin contenedor, mina al instante y acepta la misma tx legacy con `gasPrice=0` desde una cuenta sin ETH; `smoke.sh` pasa sin cambios contra los dos. Se pierde validar contra el cliente de la spec (QBFT, `min-gas-price` de Besu); para que el cambio de vuelta sea solo de URL, el código usa únicamente RPC estándar `eth_*`.

## Qué entra y qué se recorta

| Pieza | En 5 días | Recortado (queda para después) |
|---|---|---|
| TSS | tss-lib 2-de-3: DKG, firma, reshare; parte `user` en WASM | Benchmarks formales, TinyGo |
| OpenBao | `openbao-a` y `openbao-b` con transit + kv-v2 + AppRole + audit | `openbao-coord`, PKI, rotación de keys |
| Transporte | coordinador relaya por WebSocket; E2E con NaCl box; claves de los signers fijas y pinned | gRPC + mTLS (los signers hablan HTTP/WS en la red interna de Docker) |
| Auth | OTP con proveedor `console`; JWT ES256 firmado con una clave local; step-up para reshare | Twilio, rate limit, argon2id (hash simple), `client_credentials` completo |
| Cadena | Anvil (nativo) con chainId 7773, gas 0 y TestToken; la wallet es una EOA cuya dirección sale de la pubkey TSS; tx firmadas con EIP-155 y enviadas con `eth_sendRawTransaction` | Besu (QBFT, 4 nodos); ERC-4337 (EntryPoint, SimpleAccount, bundler) fuera de alcance |
| Front | `/login`, `/wallets`, `/wallets/:id`, `/recover`; share con PIN en IndexedDB | Passkey PRF, diseño |
| Headless | `mode: operators` y un script `app-wallet.ts` con la parte `app` en Go | JWT de aplicación separado (usa el mismo JWT de prueba) |
| Pruebas | script de aceptación con los flujos A a E | Prueba de carga, grep de logs en CI, demo grabada |

## Día a día

| Día | Trabajo | Gate al final del día | Plan B si falla |
|---|---|---|---|
| 1 | `pkg/tss`: DKG + firma + reshare con 3 partes en proceso (`go test`). Build WASM y página que corre DKG y firma contra 2 partes Go. En paralelo: cadena local y TestToken desplegado | El browser firma un hash contra 2 partes Go; `smoke.sh` mina una tx firmada con una clave normal | Parte `user` en un proceso Go local que el front llama por localhost; la demo sigue, pero sin TSS dentro del browser |
| 2 | `signer` con OpenBao (transit encrypt/decrypt, kv, AppRole, audit) y validación de la tx (decodifica RLP, verifica chainId, aplica la policy a `to`, `value` y `data`) con recálculo del hash a firmar. `coordinator` con sesiones, relay WS, policy y dirección derivada de la pubkey (keccak de la clave pública). CLI que hace de parte `user` | Flujo A (crear wallet) por CLI; la dirección coincide en A, B y CLI; el audit muestra el `transit/encrypt` | — (si se atrasa, se corre el día 3) |
| 3 | Firma end-to-end: la CLI arma la tx (nonce con `eth_getTransactionCount`, gas 0), corre la ronda con signer-a, arma `v`, `r`, `s` y la envía con `eth_sendRawTransaction`. Fallback a signer-b. `otp-service` mínimo con `console` y JWT | Flujo B por CLI: transferencia de TestToken minada; con signer-a apagado pasa por signer-b; un decrypt por firma en el audit | — (sin bundler, el día 3 tiene margen) |
| 4 | Front: login OTP, crear wallet (DKG en WASM), enviar con PIN. Reshare con `key_version+1` y destrucción de versiones viejas en kv-v2; pantalla `/recover` | Flujos A y B desde el browser; flujo D: browser nuevo recupera la misma dirección y la share vieja ya no firma | Reshare solo por CLI; el front queda en crear y enviar |
| 5 | Modo `operators` y `app-wallet.ts` (flujos C y E). Script de aceptación con los flujos A a E. Margen para lo que se haya atrasado | Los criterios de aceptación de abajo pasan con un comando | Se presenta con los flujos que pasan; los que no, quedan anotados |

## Criterios de aceptación (5 días)

- [ ] Crear wallet desde el browser: la dirección coincide entre front, signer-a y signer-b
- [ ] Una transferencia de TestToken firmada en modo usuario se mina en la cadena local
- [ ] Con signer-a apagado, la misma transferencia pasa por signer-b
- [ ] Un destino fuera de `allowed_to` devuelve `403 policy_denied` y ningún signer descifra su share (audit)
- [ ] El modo `operators` firma sin la tercera share solo si `operators.enabled=true`
- [ ] Reshare a un browser nuevo mantiene la dirección y la share vieja no produce firmas válidas
- [ ] Apagar y levantar los dos OpenBao (con unseal) no pierde ninguna wallet
- [ ] Ningún log contiene teléfono, JWT ni bytes de share

## Huecos de la spec: qué se resuelve en estos 5 días

| # | Problema | En 5 días |
|---|---|---|
| 1 | Claves efímeras de la ronda 0 sin autenticar: el coordinador puede hacer MITM | **Parcial:** los signers firman sus claves efímeras con una clave fija, pinned en el front y en el otro signer. Queda abierto que el coordinador se haga pasar por el browser ante los signers; se documenta como limitación conocida |
| 2 | El signer valida el payload pero no dice que firme el hash calculado por él | **Sí**, día 2: el signer recalcula el hash EIP-155 de la tx que validó y firma solo ese |
| 3 | kv-v2 deja leer la share vieja después del reshare | **Sí**, día 4 (`max_versions=1` o `destroy`) |
| 4 | El coordinador puede emitir certificados de signer | No aplica: sin PKI ni mTLS en estos 5 días |
| 5 | Falta `client_credentials` | Recortado: el script headless usa un JWT de prueba |
| 6 | La policy del signer no cubre `kv/preparams/*` | **Sí**, día 2 |
| 7–9 | Inconsistencias de texto (presigning, rol de signer-b, objetivo de DKG) | Se corrigen en la spec |
| 10 | El coordinador calcula una dirección contrafactual | No aplica: la dirección es la de la EOA |
| 11 | `jti` de un solo uso por token o por firma | `jti` por request de firma |
| 12 | La policy no limita el monto de ERC-20 | Opcional día 5: el signer decodifica `transfer(to, amount)` y aplica `max_token_amount`; si no entra, limitación aceptada |

Sin verificar: hasta donde recuerdo, el README de bnb-chain/tss-lib describe GG18 y no GG20. Se confirma el día 1 al fijar la versión v2.x.

## Riesgos

| Riesgo | Cuándo aparece | Qué se hace |
|---|---|---|
| tss-lib en WASM no cierra el DKG o los preparams tardan minutos | Día 1 | Preparams en Web Worker durante el login; si no alcanza, plan B del día 1 |
| Diferencias Anvil/Besu aparecen al volver a Besu | Después del PoC | Solo RPC `eth_*` estándar y tx legacy EIP-155; `smoke.sh` ya pasó contra Besu 26.11 el día 1 |
| Recovery id (`v`) de la firma TSS | Día 3 | Usar el recovery id que devuelve tss-lib; si no viene, probar 0 y 1 contra la dirección esperada |
| Reshare entre conjuntos de partes distintos en tss-lib | Día 4 | Probar el reshare ya el día 1 en el test en proceso |
| Todo depende del día 1 | Día 1 | No empezar el día 2 sin el gate; un día de atraso consume todo el margen del día 5 |

## Estructura del repo

```
shardsign/
  go.work
  pkg/          Go compartido: tss, transport, policy, jwt, evmtx
  signer/       servidor HTTP/WS, cliente OpenBao, rondas TSS
  coordinator/  REST, relay WebSocket, policy
  otp-service/  OTP con proveedor console, JWT
  wasm/         build de pkg/tss a WebAssembly
  web/          Vite + React + viem
  contracts/    Foundry: TestToken
  infra/        docker-compose.yml (OpenBao, servicios), openbao/
  scripts/      smoke.sh, app-wallet.ts, acceptance.sh
```
