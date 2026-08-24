---
name: debug-logs
description: Read wallet-core's structured log output while debugging -- use when investigating a runtime failure or a warn/error a call site emits, a torn ceremony or a "logged and skipped" sweep stage, or when a test needs to assert on (or silence) logged events.
---

# Reading wallet-core's structured logs

Every diagnostic in this package dispatches through the `log` seam in
`src/log.ts` -- a structural port of `@interop/logger`'s four-method
`Logger` (debug/info/warn/error), deliberately declared locally so
`dist/` carries no reference to the package. The library never
formats, filters, or namespaces; it emits `log.warn(msg, data)` and
the host decides where that lands.

Event shape: `msg` is static and greppable; the variables ride in
`data`; an error rides as `data.err` (an Error-ish value, `cause`
included). To find every emitting call site:

```bash
grep -rn "log\.\(debug\|info\|warn\|error\)" src/
```

## Where events land

- **Unwired** (vitest, a bare Node consumer): the console fallback --
  same channel and level as `console.*`, prefixed `[wallet-core]`,
  with `data` as one trailing argument. A `[wallet-core]` line in test
  output means a suite forgot to install a capture logger.
- **Wired**: an app calls `setLogger(...)` once at bootstrap and every
  call site -- including ones bound at import time -- forwards to it.
  `setLogger` returns the previous logger so a caller can restore it.

## Namespaces

Wallet-core mints no namespaces. The whole package logs through the
one flat seam, and the namespace on an event is whatever logger the
host installed: freewallet wires `setLogger(createLogger('wc'))`, so
every wallet-core event arrives there under the bare `wc` namespace
(filter: `wc` or `wc*`). The `wc:session:*` / `wc:ui:*` style
sub-namespaces in freewallet's log stream are freewallet's own call
sites; nothing under `wc:<sub>` originates here. Within wallet-core's
events, discriminate by the static `msg` string, not by namespace.

Debug-level gating is also host-side: the fallback and any wired
logger receive all four levels, and `@interop/logger`'s filter
grammar (localStorage key `interop:logger` in a browser host) decides
what surfaces.

## Debugging inside a consuming app

There is no browser app, dev server, or NDJSON sink in this repo.
When a wallet-core event needs chasing in a running wallet, debug in
the app's checkout with its own tooling -- freewallet's `debug-logs`
skill covers `window.__fwLog`, the `.dev-logs/app.ndjson` file, and
its filter loop; wallet-core's events are the bare-`wc` lane there.

## In tests

- Assert on logs with `captureLogger()` from `@interop/logger`:
  install via `setLogger(capture.logger)` in `beforeEach`, restore the
  returned previous logger in `afterEach`.
  `test/node/clients-rosterPolicy.test.ts` is the working example;
  `test/node/log.test.ts` covers the seam itself (fallback shape,
  restore, mutual assignability with the package's `Logger`).
- A suite that only needs a warn-heavy path quiet installs
  `captureLogger().logger` and never reads it
  (`test/node/clientAnnex-forgetLast.test.ts`).
- Use the seam, not `vi.spyOn(console, ...)` -- the fallback's prefix
  and trailing-argument shape make console spies brittle.
