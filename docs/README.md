# nwc-mobile documentation

This documentation is organized around the work an application team performs
when adopting `nwc-mobile`. The repository README is intentionally a short
overview; implementation details live here.

## Start here

1. Read the [getting-started guide](getting-started.md) for the complete adoption
   sequence and definition of done.
2. Read [architecture](architecture.md) before deciding which code belongs in
   the wallet and which belongs in `nwc-mobile`.
3. Implement the [Lightning node](integration/lightning-node.md) and
   [`NwcMobile` composition root](integration/nwc-mobile.md).
4. Add [NWA](integration/nwa.md) and [NWC connection UI](integration/nwc-ui.md).
5. Wire [iOS](integration/ios-background.md) or
   [Android](integration/android-background.md) background execution.
6. Connect the wallet to a separately deployed
   [wake service](integration/wake-server.md).
7. Exercise the [testing checklist](testing.md) on a physical device.

## Integration guides

- [Configuring `NwcMobile`](integration/nwc-mobile.md)
- [Implementing `NwcLightningNode`](integration/lightning-node.md)
- [Nostr Wallet Auth](integration/nwa.md)
- [NWA and NWC screens](integration/nwc-ui.md)
- [iOS background execution](integration/ios-background.md)
- [Android background execution](integration/android-background.md)
- [Wake-service integration](integration/wake-server.md)

## Design and operations

- [Architecture and ownership boundaries](architecture.md)
- [Protocol and background flows](flows/README.md)
- [Security model](security.md)
- [Testing an integration](testing.md)
- [Rebel Wallet reference integration](rebel-wallet-example.md)

## Package references

The native packages retain their exact API and wiring references:

- [NwcMobileApple](../apple/NwcMobileApple/README.md)
- [nwc-mobile Android](../android/nwc-mobile/README.md)
- [Generated binding contract](../bindings/README.md)

Contributor, release, and dependency policies remain at the repository root:
[CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](../SECURITY.md),
[SUPPLY_CHAIN.md](../SUPPLY_CHAIN.md), and [RELEASING.md](../RELEASING.md).

## Documentation ownership

Conceptual behavior belongs in `docs/`. Exact native package APIs belong beside
their package. Rust API signatures belong in rustdoc and should be linked from
the guides instead of copied repeatedly. When behavior changes, update the
guide that owns the concept and any end-to-end flow affected by it.
