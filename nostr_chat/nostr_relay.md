# Nostr Relays — Notes

## Next Steps

1. **Explore region-specific relays** for improved latency in Asia:
   - **Japan**: `wss://relay.nostr.wirednet.jp`, `wss://relay-jp.nostr.wirednet.jp`, `wss://nostr.h3z.jp`, `wss://nostr.inosta.cc`, `wss://nostr.holybea.com`, `wss://crystal-nostr-relay.compile-error.net` — see `github.com/mattn/awesome-nostr-japan`
   - **China**: `wss://relay.gulugulu.moe` (咕噜咕噜 relay), `wss://relay.nostr.moe` (needs registration) — see `github.com/nostr-zh/awesome-nostr-zh`
   - **Singapore**: No specific relay found — verify if `relay.damus.io` or `relay.nostr.band` has optimal routing
   - **Korea**: No specific relay found — `wss://nostr.inosta.cc` (Japan-based) likely lowest latency
   - General directory: `github.com/CodyTseng/awesome-nostr-relays` with `dist/relays.json`
2. **Debug C↔Go cross-version signature verification** if interop issues arise
3. **Consider adding support for `wss://`/`ws://` URL handling** without the `fiatjaf.com/nostr` `NormalizeURL` dependency

## Critical Context

- `fiatjaf.com/nostr` handles Schnorr signing, WebSocket connection, and subscription channels automatically — no direct libcurl/secp256k1 needed
- Nostr relay behavior for ephemeral kind 22334 varies significantly:
  - `wss://relay.damus.io`: ✅ accepts publish, ✅ forwards live to subscribers
  - `wss://nos.lol`: ✅ accepts publish, ❌ does not forward live to other subscribers (only replays stored events via REQ)
  - `wss://pyramid.fiatjaf.com`: ❌ "blocked: kind unallowed"
  - `wss://relay.nostr.info`: ❌ "kind 22334 not permitted"
  - `wss://eden.nostr.land`: ❌ requires payment
- Directed messaging requires relay support for `#p` tag indexing (NIP-01)
- Even without `-a` app tag, `-p` mode alone isolates different user groups effectively
- Go version keeps running after stdin EOF (`<-ctx.Done()`) for background receive mode
- `nostr.Publish(ctx, event)` waits for relay OK response (7s timeout) before returning
- Search results for Asia-region Nostr relays point to `nostr.wirednet.jp`, `nostr.h3z.jp`, `nostr.inosta.cc`, and `relay.gulugulu.moe` as active candidates
