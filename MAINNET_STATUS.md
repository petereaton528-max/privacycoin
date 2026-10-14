# Privacy Coin Mainnet status

Privacy Coin Mainnet was activated on **2026-10-14**. The launch details below
are owner-reported production observations.

**This is an early single-node Mainnet. Independent public connectivity has not
yet been verified.** The initial seed is bootstrap assistance; its publication
does not establish independent peers, decentralization or continuous availability.

| Launch parameter | Value |
| --- | --- |
| Network | `PCMainnetV1_0001` |
| Approved Genesis | `6233402308514d2d979a9efa9c6bd2f9843741598f1e5b18239cde16ba0d2b54` |
| First production block | Height **1** |
| Block 1 hash | `3d03a4f979ee3d4669cccdcac9d56c41a48f53fad60c24a8f60874b80612599f` |
| First mining reward | **35.184372088831 PC**, initially immature |

Mining rewards are subject to the consensus maturity requirement of 60 blocks.
The height and reward above describe the first-block observation, not a live status feed.

## Public initial seed

```text
pcnode://ar25o2ni2xn3izeo2ihaxg2btdnxj3g6kbw674usqkezaqoc76wxihqd.onion?pin=c0c61ac19ba501ada54a50f82ff3494b9950ce7ba94a6812dac5744200b80ab8&network=PCMainnetV1_0001
```

Use the exact network and TLS pin. Ordinary node joining requires no private
invitation or owner-issued admission ticket. Tor bootstrap alone is not proof
of authenticated peer connectivity or correct chain synchronization.

## Security and release status

**AI-assisted internal review only. No independent third-party security audit has been performed.**

Privacy Coin is new and RC1 remains an early unaudited release candidate. Material
risks include loss of wallet funds, privacy limitations, hostile peers and networks,
resource exhaustion, software or consensus bugs and weak initial network security.
No security, anonymity, profitability or availability guarantee is made. Review
[the security disclosure](SECURITY_DISCLOSURE.txt) and
[known limitations](KNOWN_LIMITATIONS.md).

The RC1 release notes retain their publication-time status. This announcement
records the subsequent owner-authorized activation; it does not alter the signed
RC1 archives or extend their signature to this document.
