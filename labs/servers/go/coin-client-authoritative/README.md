# coin-client-authoritative

> **Intentionally vulnerable, local lab only.** Bind it to loopback and never
> deploy it. The account and purchase code is deliberately realistic, but the
> wallet compatibility path contains a documented CWE-602 flaw.

This is a standalone Go module. It does not import `mega-analyzer`, `netproxy`,
or any MITM component. The analyzer is an external client/proxy and sees only
ordinary HTTP or TCP bytes, exactly as it would with an unrelated server.

## What the lab contains

- Browser shop at `http://127.0.0.1:18110`
- Registration and password login (PBKDF2-SHA-256 with random salts)
- HttpOnly, SameSite session cookies; tokens are hashed in the database
- Persistent bbolt database with users, balances, sessions, and inventory
- Four real products and an atomic purchase transaction
- A packet-processing task that earns 15 server-issued coins with a cooldown
- Settings with logout and password-confirmed account deletion
- Legacy length-prefixed TCP protocol at `127.0.0.1:18010`

The browser starts a new account with 35 coins, so the 25-coin patch cable can
be purchased without an exploit. More expensive items require earned coins or
completion of the coin-injection exercise.

## Correct purchase invariant

The purchase request contains only an item ID. The server reads both the item
price and account balance, then performs the debit and inventory write in one
database transaction:

```go
if user.Balance < product.Price {
    return errInsufficientFunds
}

user.Balance -= product.Price
// save user + increment inventory in the same bbolt transaction
```

Unknown JSON fields are rejected, so adding `client_balance` or `price` to
`POST /api/buy` cannot influence authorization.

## The single intentional vulnerability

An obsolete recovery route still accepts a client's unsigned cached wallet
snapshot:

```http
POST /api/wallet/reconcile
Content-Type: application/json

{"reported_balance":35}
```

`ReconcileLegacyBalance` promotes a higher `reported_balance` into the
authoritative database. A MITM can rewrite `35` to `777` while the request is
in transit. A later `POST /api/buy {"item_id":2}` passes the otherwise-correct
server-side check because the legacy boundary already poisoned server state.

The TCP compatibility path demonstrates the same boundary with
`[clientBalance][itemID]`: the field is reconciled first, then the independent
server-authoritative purchase function runs. The external test
`TestCoinLabMITM_ForgeBalance` rewrites this field in transit. Without the
proxy, the honest request is denied.

This split is intentional: authentication, password verification, product
prices, the purchase transaction, logout, and deletion do not contain planted
bypasses. Only legacy wallet reconciliation is vulnerable.

## Wire protocol

Frames use big-endian length-prefixed encoding:

```text
[2B msgType][4B payloadLen][payloadLen bytes payload]
```

| msgType | Direction | Name | Payload |
| --- | --- | --- | --- |
| `0x0001` | client to server | Hello | none |
| `0x0010` | client to server | BuyItem | `[4B legacyBalance][2B itemID]` |
| `0x0020` | client to server | GetState | none |
| `0x8001` | server to client | Welcome | `[4B balance]` |
| `0x8010` | server to client | BuyOK | `[4B balance]` |
| `0x8011` | server to client | BuyDenied | reason string |
| `0x8020` | server to client | State | `[4B balance]` |
| `0x80ff` | server to client | Error | reason string |

## Run locally

```sh
cd labs/servers/go/coin-client-authoritative
GOWORK=off go run .
```

Open `http://127.0.0.1:18110`. Runtime data is written to `coin-lab.db` and is
ignored by git.

Configuration:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LISTEN_ADDR` | `127.0.0.1:18010` | Legacy TCP listener |
| `HTTP_LISTEN_ADDR` | `127.0.0.1:18110` | Browser shop and API |
| `DB_PATH` | `coin-lab.db` | Embedded database file |
| `HTTP_DISABLED` | empty | Set to `1` for raw TCP only |

When only `LISTEN_ADDR` is explicitly set, the process runs in TCP-only mode.
This keeps the external MITM integration fixture isolated and free of hidden
HTTP or database requirements.

## Tests

```sh
cd labs/servers/go/coin-client-authoritative
GOWORK=off go test ./...
```

The tests cover framing, the secure purchase invariant, the intentional
reconciliation exploit, real shop purchases, persistence, earn cooldown,
logout, and account deletion.
