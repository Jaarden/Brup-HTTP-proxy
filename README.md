# BRUP

An intercepting HTTP proxy with Repeater and Intruder, driven entirely from your
web browser. Everything runs in Docker.

```
┌─ your browser ──────────┐        ┌─ brup container ─────────────────────┐
│  UI at :9080            │───────▶│  FastAPI + React UI                  │
│  traffic proxied to     │        │                                      │
│  :9081                  │───────▶│  asyncio MITM proxy ──▶ the target    │
└─────────────────────────┘        │  SQLite history on /data volume      │
                                   └──────────────────────────────────────┘
```

## Contents

- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [Where the data lives](#where-the-data-lives)
- [Projects](#projects)
- [Settings: system and project](#settings-system-and-project)
- [Routing through a VPN](#routing-through-a-vpn)
- [Point a browser at it](#point-a-browser-at-it)
- [Install the CA certificate](#install-the-ca-certificate)
- [Proxy and interception](#proxy-and-interception)
- [HTTP/2](#http2)
- [Header rules](#header-rules)
- [Sitemap](#sitemap)
- [Invisible proxying](#invisible-proxying)
- [Repeater](#repeater)
- [Intruder](#intruder)
- [Reaching your target](#reaching-your-target)
- [Configuration reference](#configuration-reference)
- [Development](#development)
- [Design notes and limits](#design-notes-and-limits)
- [Authorised use](#authorised-use)

## What it does

| Feature | Notes |
| --- | --- |
| **Projects** | Isolated workspaces in the left sidebar. Each owns its history, sitemap, Repeater tabs and Intruder attacks, and can override the system settings. |
| **HTTP/2** | h2 to the browser and to the origin, with transparent downgrade when the origin only speaks HTTP/1.1. Intercept, edit, Repeater and Intruder all work over h2. |
| **Intercepting proxy** | Holds requests (and optionally responses), lets you edit the raw bytes, then forward or drop. |
| **HTTP history** | Every exchange logged to SQLite with search, host/method/source filters, scope filter, notes and colour highlights. |
| **VPN** | Import an OpenVPN `.ovpn` or WireGuard `.conf` file and route all proxy traffic through it, with a kill switch that refuses to send anything when the tunnel is down. |
| **Header rules** | Rewrite request or response headers on proxied traffic per project — set `X-Forwarded-For`, strip a CSP — from a dropdown of common headers. |
| **Sitemap** | Host/path tree built from history, with per-node item lists, scope shortcuts and hand-off to Repeater/Intruder. |
| **Proxy settings** | Listener address and port, scope rules, upstream proxy, TLS pass-through, timeouts, history limits — all editable live in the UI. |
| **Invisible proxy** | Accepts requests from clients that do not know they are proxied, including a separate SNI-based listener for redirected HTTPS. |
| **Repeater** | Tabbed request editor; resend and tweak by hand, with a per-tab trail you can step back through. |
| **Intruder** | Payload positions marked with `§`, all four attack types (sniper, battering ram, pitchfork, cluster bomb), wordlists, payload processing rules, grep-match, live streaming results. |

## Quick start

```bash
docker compose up -d --build
```

Then open **<http://localhost:9080>**.

Tabs are held in the URL hash, so a view survives a reload and can be linked:
`#proxy/history`, `#intruder/results`, or a specific sitemap node such as
`#sitemap/https%3A%2F%2Fexample.com%2Fapp`.

Three ports are published:

| Port | Purpose |
| --- | --- |
| `9080` | Web UI and API |
| `9081` | **Proxy listener** — point your browser here |
| `9444` | Invisible-HTTPS listener (only used if you enable it) |

All three are published on every interface by default, so the proxy is usable
from another machine. **`BRUP_BIND`** changes that, and **`BRUP_UI_BIND`**
overrides it for the UI alone:

| Setting | Effect |
| --- | --- |
| unset | All three ports on `0.0.0.0` — reachable from your network. |
| `BRUP_BIND=127.0.0.1` | Localhost only; nothing on the network can reach BRUP. |
| `BRUP_UI_BIND=127.0.0.1` | The UI stays local while the proxy remains reachable from the LAN. |

That last combination is the one to reach for when proxying a phone or another
VM: the UI has **no authentication**, so anyone who can reach port 9080 controls
the proxy and can read every project's history.

The 90xx range is used rather than the more obvious 8080/8081 because those are
commonly already taken by other local services. Host and container ports are kept
identical, so the address the settings page reports is the one you connect to. To
change them, edit both `docker-compose.yml` and the listener port in settings.

State lives in a Docker volume by default and survives restarts and rebuilds, so
you install the CA once. See [Where the data lives](#where-the-data-lives) to put
it in a directory of your choosing instead.

To start over completely:

```bash
docker compose down -v      # -v also deletes the volume, including the CA
```

A database written before projects existed cannot be upgraded in place — BRUP
refuses to start against one and tells you to run the command above rather than
risk mangling it.

## Where the data lives

Everything BRUP keeps is in one directory: the CA key and certificate,
`settings.json`, and `brup.sqlite3` holding every project's history, sitemap,
Repeater tabs and Intruder results.

Set **`BRUP_DATA`** to choose where that is. Copy `.env.example` to `.env` and
uncomment the line you want — `docker compose` reads `.env` automatically:

| `BRUP_DATA` | Result |
| --- | --- |
| unset, or `brup-data` | A named Docker volume (the default). Docker manages the location. |
| `./data` | A directory beside `docker-compose.yml`. |
| `/srv/brup/data` | Any absolute path on the host. |

Anything starting with `/` or `.` becomes a bind mount; anything else is treated
as a named volume. A one-off run without touching `.env` works too:

```bash
BRUP_DATA=/srv/brup/data docker compose up -d
```

A host directory is easier to back up, inspect and move between machines. The
trade-off is ownership: the container runs as root, so the files are root-owned
and you will need `sudo` to read or delete them from the host.

`BRUP_DATA_DIR` sets where that data is mounted *inside* the container
(default `/data`). It is rarely worth changing; the application reads the same
variable, so the mount and the code cannot disagree.

### Moving existing data to a directory

Stop the container first, so SQLite checkpoints its write-ahead log into the main
database file:

```bash
docker compose down
docker run --rm -v brup_brup-data:/from -v /srv/brup/data:/to alpine \
    sh -c 'cp -a /from/. /to/'
echo 'BRUP_DATA=/srv/brup/data' >> .env
docker compose up -d
```

The volume is named after the Compose project, which comes from the directory
name — `brup_brup-data` here. `docker volume ls` will confirm it. The CA,
projects and VPN profiles all come across, so nothing needs reinstalling.

## Projects

The left sidebar lists your projects; click one to open it. A project is an
isolated workspace holding **its own** HTTP history, sitemap, Repeater tabs and
Intruder attacks — switching project swaps all of it at once, so two engagements
never mix.

**BRUP starts in a temporary project**, as Burp does. With nothing else to open
it creates one called *Temporary project*, marked ⏱ in the sidebar and the top
bar. Its work is **discarded when BRUP restarts** — so poking at something costs
you nothing, and keeping it is a deliberate act. Press **keep** beside it, or
create a named project with **+ New project**, and it survives from then on.
Projects you made yourself are never temporary unless you asked for one.

- **+ New project** creates one. "Copy settings" starts it from the current
  project's setting overrides, which saves redoing scope rules for a second
  target on the same engagement.
- **⏱ Temporary project** creates another scratch workspace, named for the
  current time — for a quick look at something you do not want cluttering the
  list. Press **keep** on any temporary project to promote it.
- **Double-click** a project (or edit the name field in Project settings) to
  rename it.
- **×** deletes it, after confirming — that permanently removes its history,
  sitemap, Repeater tabs and Intruder results. The last remaining project cannot
  be deleted; clear its history instead.
- **‹** collapses the sidebar when you want the width back.

Names are free text and are only ever rendered as text, so a name like
`<h1>test` shows up literally rather than being interpreted.

What is **not** per project, and why:

| Shared | Reason |
| --- | --- |
| The CA certificate | One authority for all projects, so you install it in your browser once. |
| The proxy listener | There is one listener process; its address and port are system settings. |
| Wordlists | Reusable tooling rather than engagement findings, so they are available everywhere. |
| The VPN tunnel | One network namespace means one tunnel; a project cannot have its own, or switch off the kill switch. |
| The intercept queue | It belongs to the shared listener. A message held when you switch project stays visible and forwardable — otherwise the browser connection would hang with nothing able to release it — and is tagged with the project that captured it. It is logged against that project, not the one you switched to. |

The active project is remembered, so a restart reopens where you left off.

## Settings: system and project

There are two tiers, and the project tier wins:

**System settings** (sidebar → ⚙ System settings) are the defaults for every
project, plus the things that cannot be per project: the **proxy listener**
address and port, the **invisible HTTPS listener**, and the **CA certificate**.
Those four listener settings bind sockets and need a restart, so they are marked
`system only` and a project cannot override them.

**Project settings** (Proxy → Project settings) override the system defaults for
the open project only. Every behavioural setting can be overridden: interception,
scope, upstream proxy, timeouts, TLS pass-through, invisible proxying and history
limits.

Each row shows where its value comes from:

- Booleans are a single three-way control — **Inherit (off)**, **On**, **Off** —
  so there is never a question of whether a checkbox means "override" or "value".
- Other settings have an **override** switch; while it is off the control is
  greyed out and the row reads `inherits <system value>`.
- **Clear all overrides** drops the project back to the system defaults entirely.

So a typical setup is: put the timeouts, pass-through hosts and skip-extensions
you always want into System settings once, then per project override only the
scope rules and whether interception is on.

Toggling interception from the Proxy → Intercept toolbar writes a **project**
override, because that is nearly always what you mean.

## Routing through a VPN

**System settings → VPN** imports an OpenVPN or WireGuard configuration and
brings the tunnel up inside BRUP's own network namespace. Once it is a full
tunnel, every upstream connection the proxy makes — proxy, Repeater and Intruder
alike — goes through it.

### Prerequisites

Creating a network interface needs privileges the compose file already grants:

```yaml
cap_add:  [NET_ADMIN]
devices:  [/dev/net/tun:/dev/net/tun]
sysctls:  { net.ipv4.conf.all.src_valid_mark: "1" }
```

The image ships `openvpn`, `wireguard-tools` and `wireguard-go`. WireGuard uses
the host's kernel module when it can reach it and falls back to the userspace
implementation when it cannot.

### Importing a profile

1. **+ Import configuration**, then paste the config or **Load from file…** a
   `.ovpn` / `.conf`.
2. BRUP detects which client it is for and shows what the config will actually
   do: the endpoint, whether it is a **full** or **split** tunnel, the address
   and DNS it will use, and warnings for anything that will surprise you — a
   missing `redirect-gateway`, `AllowedIPs` that is not `0.0.0.0/0`, an
   `auth-user-pass` pointing at a file that will not exist in the container.
3. Username and password are optional; fill them in only if your provider uses
   them (OpenVPN configs with a bare `auth-user-pass` line do).
4. **Connect**. **Auto** connects that profile whenever BRUP starts.

Only one tunnel can be up at a time, and it cannot vary per project — there is a
single network namespace. That is why every VPN setting is `system only`.

### The kill switch

**Require VPN** is the setting that makes this trustworthy. While it is on and
the tunnel is not up, the proxy, Repeater and Intruder all refuse to send
anything and log the refusal, rather than quietly falling back to your normal
connection. Turn it on if traffic must never leak.

### Verifying it works

**Check exit IP** asks an external service (`https://api.ipify.org` by default,
configurable) which address your traffic appears to come from — the only way to
confirm from in here that the tunnel is really carrying traffic. It is a manual
button because it contacts a third party.

**Show log** has the full client output, which is where to look when a connection
fails.

The **top bar** carries a VPN badge from anywhere in the app, so you never have to
go looking for the current state:

| Badge | Meaning |
| --- | --- |
| `● VPN on · 188.95.55.26` (green) | Tunnel up; traffic exits from that address. The address appears once you have pressed **Check exit IP**. |
| `● VPN connecting…` (amber) | Tunnel coming up. |
| `● VPN off` (grey) | No tunnel, and the kill switch is off — traffic goes out over your normal connection. |
| `● VPN off · blocking` (red) | The kill switch is on with no tunnel, so every request is being refused. |
| `● VPN failed · blocking` (red) | The tunnel failed; hover for the reason. |

Clicking the badge opens System settings. The exit IP is cleared when the tunnel
goes down, so it can never show a stale address.

### What to expect once connected

- **BRUP stays reachable, including from other machines.** A full tunnel takes
  over the default route, which would otherwise swallow the *replies* to
  connections that arrived from elsewhere — the UI and the proxy port would stop
  answering anything but a local client. BRUP marks inbound connections in
  conntrack and routes their replies back out over the host's original default
  route, so remote access keeps working while everything the proxy sends still
  goes through the tunnel.

  This matters as soon as BRUP is not on the machine you browse from — a NAS
  under Portainer, a VM, a lab box. A local client happens to work either way,
  because Docker masquerades it into the bridge subnet where a more specific
  route still applies; a client on your LAN does not.

  It needs the `conntrack` iptables match, which the shipped image has. If the
  kernel lacks it, BRUP logs that remote access may fail and leaves the tunnel
  up rather than refusing to connect. **Show log** will say so.
- **DNS follows the tunnel.** If the config specifies DNS, BRUP points
  `/etc/resolv.conf` at it so lookups do not leak, and restores the original on
  disconnect. A consequence worth knowing: if the tunnel is broken, name
  resolution fails too — including for hosts on your own LAN.
- **Local subnets keep their direct route**, so a target addressed by IP on the
  Docker network is still reachable.

### Limitations

- One tunnel at a time, system-wide.
- Replies to inbound connections bypass the tunnel by design, so that BRUP
  itself stays reachable. Traffic BRUP *sends* — everything the proxy, Repeater
  and Intruder do — always goes through it.
- Credentials and configs are stored in the `/data` volume in plain text, like
  the CA key. Anyone with access to that volume can read them.
- IPv6 inside the tunnel is left to the VPN client; BRUP does not add its own
  IPv6 routes.
- A kill switch at the application layer stops *BRUP* from sending outside the
  tunnel. It is not a firewall: it does not constrain other processes.

## Point a browser at it

Configure your browser's HTTP **and** HTTPS proxy to `127.0.0.1:9081`.

Use a separate browser or profile for testing — once the CA is installed, BRUP
can read everything that browser sends over TLS.

**Firefox** (has its own proxy settings, which is why it is convenient here):
Settings → search "proxy" → Network Settings → Settings… → Manual proxy
configuration → HTTP Proxy `127.0.0.1`, Port `9081`, tick "Also use this proxy
for HTTPS".

**Chrome/Chromium** uses the system proxy, so it is cleanest to launch a
throwaway profile:

```bash
chromium --proxy-server="http://127.0.0.1:9081" \
         --user-data-dir=/tmp/brup-profile
```

**curl**, for a quick check:

```bash
curl -x http://127.0.0.1:9081 http://example.com/
```

## Install the CA certificate

HTTPS interception works by presenting certificates BRUP signs itself, so the
client has to trust BRUP's CA. Download it from **Proxy → Proxy settings → CA
certificate**, or directly:

```bash
curl -O http://localhost:9080/api/ca/cert.pem      # PEM, for Firefox / curl / Linux
curl -O http://localhost:9080/api/ca/cert.der      # DER, for Windows / Android
```

**Firefox:** Settings → Privacy & Security → Certificates → View Certificates →
Authorities → Import → pick `brup-ca.pem` → tick **"Trust this CA to identify
websites"**.

**macOS:** double-click the `.pem`, add to the login keychain, then set it to
"Always Trust" in Keychain Access.

**Windows:** `certutil -addstore -user Root brup-ca.der`.

**curl:** `curl -x http://127.0.0.1:9081 --cacert brup-ca.pem https://example.com/`

Verify it is working — the certificate your browser sees should be issued by
`BRUP Proxy CA`:

```bash
echo | openssl s_client -proxy 127.0.0.1:9081 -connect example.com:443 \
       -servername example.com 2>/dev/null | openssl x509 -noout -subject -issuer
# subject=CN = example.com
# issuer=CN = BRUP Proxy CA, O = BRUP
```

Only install this CA where you intend to intercept traffic. Anything trusting it
can have its TLS read by whoever holds the key on the `/data` volume.

If a site refuses to load because it pins its certificate, add it to **TLS
pass-through hosts** in settings — those connections are tunnelled through
without being decrypted.

## Proxy and interception

**Proxy → Intercept** is where held messages appear.

- The big **Intercept is on/off** button is the master switch.
- **Requests** / **Responses** choose which directions get held.
- **Forward** (or `Ctrl+Enter`) sends the message on. Edit the text first and
  your edited bytes are what goes out — history marks the row `ED`.
- **Drop** abandons it and closes the connection.
- **Forward all** / **Drop all** clear the queue when it backs up.

Static assets (`.css`, `.png`, `.woff2`, …) are never held, so you are not
clicking Forward fifty times per page load. That list is editable in settings.

**Proxy → HTTP history** logs everything in the open project. Click a row to see the raw request and
response; the response viewer has **Pretty** (formatted, gzip/Brotli decoded),
**Raw**, **Headers** and **Hex** modes. Right-hand buttons send the request on to
Repeater or Intruder.

**Scope** rules are regexes matched against the full URL. With any include rule
set, only matching URLs are in scope. Out-of-scope traffic is still proxied so
the site keeps working — it is just never held for interception.

## HTTP/2

BRUP advertises `h2` alongside `http/1.1` in the TLS handshake and the browser
chooses. When a client picks HTTP/2, BRUP speaks HTTP/2 to the origin too — and
when the origin declines, it speaks HTTP/1.1 to the origin and translates, so
the client still gets a coherent HTTP/2 response. History records which protocol
was actually used, tagged `h2` beside the host.

### Reading and editing an HTTP/2 message

An HTTP/2 request is a set of header fields, not a request line, so there is no
one canonical text form. Messages are shown like this:

```
GET /search?q=1 HTTP/2
:authority: example.com
:scheme: https
accept: */*
cookie: a=1
```

The first line puts `:method` and `:path` where you expect them; the remaining
pseudo-headers are shown rather than hidden. Editing round-trips exactly, so what
you type is what goes on the wire.

- An explicit `:method` or `:path` header line **overrides the first line**, for
  sending something the first line cannot express.
- Pseudo-headers are reordered to the front on the way out, because HTTP/2
  rejects a pseudo-header that follows a regular one.
- Field names must be lowercase — that is HTTP/2, not a BRUP restriction.
- Repeated fields are kept separate, not merged. Browsers legitimately split
  `cookie` across several fields to help HPACK.
- Responses show a reason phrase for readability. HTTP/2 has none, so it is
  synthesised from the status code and ignored when parsed back.

### Repeater and Intruder

Both follow the request's first line. End it with `HTTP/2` and the request goes
out as HTTP/2; leave it `HTTP/1.1` and it does not. That makes comparing a
target's behaviour across the two protocols a one-word edit — often worth doing,
since request handling frequently differs between an HTTP/2 front end and the
HTTP/1.1 hop behind it.

HTTP/2 requires TLS here, so Repeater refuses an `HTTP/2` request with HTTPS
unticked rather than sending something that cannot work.

### Turning it off

| Setting | Tier | Effect |
| --- | --- | --- |
| **Advertise HTTP/2 to clients** | system | Stop offering `h2` in ALPN, forcing every client onto HTTP/1.1. |
| **Offer HTTP/2 to origin servers** | project | Stop offering `h2` upstream, forcing the origin onto HTTP/1.1 while the client may still use h2. |

The second is the interesting one: it lets you hold the client side constant and
change only what the origin sees.

### Limits

- **No h2c** (HTTP/2 without TLS). Browsers do not use it.
- **Server push is refused.** BRUP advertises `ENABLE_PUSH=0` and resets anything
  pushed anyway, rather than forwarding streams the client did not ask for.
- **Stream priority is not preserved.** It has no bearing on what a request does.
- **One upstream connection per request**, as on the HTTP/1.1 path. Client-side
  multiplexing is fully supported — a browser's concurrent streams are handled
  concurrently, and interception holding one does not block the others.
- **Trailers** arrive appended to the response header fields rather than being
  kept separate.

## Header rules

**Proxy → Project settings → Header rules** rewrites headers on traffic going
through the proxy. The usual reason is spoofing a client IP:

1. Pick from **Add a header…** — the list is grouped by intent (client IP,
   routing and host, identity, and response headers), and choosing one prefills
   both the name and a sensible value. `Custom header…` gives you an empty row.
2. Edit the value however you like.
3. Save.

Each rule is one row: **enabled**, **direction**, **action**, **name**, **value**.

| Action | Effect |
| --- | --- |
| **Set** | Replace the header, or add it if the client did not send one. Collapses duplicates. |
| **Add** | Append another instance, for headers that legitimately repeat. |
| **Remove** | Delete every instance. The value field is greyed out. |

Rules are **per project**, like the rest of Project settings, so an
`X-Forwarded-For` you need for one target does not follow you to the next. Set
them in System settings instead to have every project inherit them.

### Where they apply, and where they do not

Rules run on proxied traffic **before interception**. That ordering is
deliberate: a held request shows exactly what will be sent, and anything you
type in the Intercept window still wins over the rule. HTTP history logs the
rewritten request, so the log is what actually went out.

Repeater and Intruder are deliberately left alone — you are editing the raw
request by hand there, and silently rewriting it underneath you would be
surprising. Add the header to the request text instead.

`Content-Length` and `Transfer-Encoding` are refused with an explanation: they
carry the message framing, and rewriting them mid-exchange would desynchronise
it. A line break in a name or value is refused for the same reason. If you
genuinely want to send a bad length or a split header, Repeater gives you raw
byte control.

### Examples

| Goal | Rule |
| --- | --- |
| Look like a local request | Request · Set · `X-Forwarded-For` · `127.0.0.1` |
| Cover the whole IP-header family | One `Set` rule each for `X-Real-IP`, `X-Client-IP`, `True-Client-IP`, … |
| RFC 7239 form | Request · Set · `Forwarded` · `for=127.0.0.1;proto=https` |
| Reach an internal vhost | Request · Set · `X-Forwarded-Host` · `internal.local` |
| Let a framed page load | Response · Remove · `X-Frame-Options` |
| Disable CSP while testing XSS | Response · Remove · `Content-Security-Policy` |
| Hide your scanner | Request · Remove · `User-Agent` |

## Sitemap

**Sitemap** shows everything the proxy has seen **in the open project** as a tree
of hosts and paths. It
is derived from HTTP history on demand rather than stored separately, so it never
drifts out of step with the log — and clearing history clears the map.

Each row shows the methods seen at that path, a headline status (the worst one,
so a `500` buried in a folded branch still stands out) and a count of items in
the whole subtree. `http://` and `https://` are separate trees, labelled with
their scheme and sorted next to each other. Out-of-scope hosts are dimmed and
sort last.

Selecting a node lists its logged items on the right:

- **include sub-paths** toggles between just that path (with its query-string
  variants) and everything beneath it.
- Clicking an item opens the request and response in the usual viewer, with
  **→ Repeater** and **→ Intruder** buttons.
- **+ Host to scope** and **− Exclude branch** write an anchored regex straight
  into your scope rules, which is much quicker than typing them by hand in
  settings.

The tree refreshes itself about a second after new traffic arrives, so it grows
as you browse. **In scope only** is the fastest way to cut the noise once you
have set a scope — browser telemetry and CDN chatter disappear.

Paths that differ only by a trailing slash are merged into one node, and query
strings collapse onto the path they belong to (the individual URLs are still
listed on the right).

## Invisible proxying

A normal proxy client announces where it is going: `GET http://host/path`, or
`CONNECT host:443`. A client that does not know it is proxied just sends
`GET /path`, because it believes it is talking to the server directly.

Turn on **Invisible proxying** in settings to accept those. BRUP then takes the
destination from the `Host` header.

For redirected **HTTPS** there is no `CONNECT` to name a destination, so it gets
its own listener: enable **invisible HTTPS listener** (port `9444`). It
terminates TLS directly and picks which certificate to present from the SNI
hostname in the handshake.

Route traffic to it either by overriding DNS for the target hostname, or with a
redirect on the client machine:

```bash
# Send this host's outbound web traffic to BRUP without configuring any client.
sudo iptables -t nat -A OUTPUT -p tcp --dport 80  -j REDIRECT --to-port 9081
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 9444
```

Because a redirected connection loses the original port, the HTTPS listener
assumes the target is on port 443. The **fallback host** setting only applies to
requests that arrive with no `Host` header at all.

## Repeater

Send a request here from history or Intercept, then iterate on it. Tabs are
saved with the project, so they are still there after a restart or a switch.

- Tabs across the top; double-click a tab to rename it, `+` for a new one.
- **Host**, **Port** and **HTTPS** set where it goes — independent of whatever
  the `Host` header says, so you can point the same request at another origin.
- **Send** or `Ctrl+Enter`. Status, timing and length appear under the response.
- **Fix Content-Length** recalculates the header from the actual body, which is
  usually what you want after editing a body by hand. Turn it off to send a
  deliberately wrong length.
- **‹ Prev / Next ›** step back through what you sent earlier in that tab.

Requests sent from Repeater also land in HTTP history, tagged `RPT`.

## Intruder

**Positions** — set the target, then mark the parts of the request to replace:

- Select text and press **Add § position**.
- **Auto-mark params** marks every query-string, cookie and form-body value.
- **Clear §** removes them all.

Positions are delimited by `§`, so `id=§1§` fuzzes the value `1`. The right-hand
panel shows how many requests the attack will send and the exact first request,
updating as you type.

**Payloads** — pick the attack type and fill the payload sets:

| Attack type | Behaviour | Requests |
| --- | --- | --- |
| **Sniper** | One set. Attacks each position in turn, others keep their original value. | positions × payloads |
| **Battering ram** | One set. Puts the *same* payload in every position at once. | payloads |
| **Pitchfork** | One set per position, advanced in lockstep. Good for paired credentials. | length of the shortest set |
| **Cluster bomb** | One set per position, every combination. | product of all set sizes |

Each set is a **simple list** (typed in, or a saved/uploaded wordlist), a
**number range**, or a **brute-force character set**. **Load from file…** uploads
a wordlist and stores it for reuse; **Save as wordlist…** keeps what you typed.

**Payload processing** rules run in order on every payload — `prefix`, `suffix`,
`upper`, `lower`, `reverse`, `strip`, `url_encode`, `url_encode_all`, `base64`,
`hex`, `md5`, `sha1`, `sha256`.

**Options** — concurrency, delay between requests, a hard cap on total requests,
Content-Length recalculation, URL-encoding, and **Grep — match**: one expression
per line, and any response containing one gets flagged in the results.

**Results** stream in live. Sort by any column, filter, and click a row to see
the exact bytes sent and received. Grep hits get a yellow marker — usually the
fastest way to spot the one request that behaved differently. Pause, resume and
stop are in the toolbar.

## Reaching your target

The proxy runs inside the container, so "localhost" means the container.

| Target location | Use |
| --- | --- |
| The internet | Works as-is. |
| On your host machine | `host.docker.internal` (already mapped in `docker-compose.yml`). |
| Another container | Put it on the same Docker network and use its service name. |

For a target in Docker Compose, add BRUP to that project's network:

```yaml
services:
  brup:
    # …
    networks: [default, targetnet]
networks:
  targetnet:
    external: true
    name: yourproject_default
```

## Configuration reference

System defaults live in `/data/settings.json`; each project's overrides live in
the database alongside its history. `system only` marks the four settings a
project cannot override.

| Setting | Default | Meaning |
| --- | --- | --- |
| `proxy_host` / `proxy_port` *(system only)* | `0.0.0.0` / `9081` | Main listener. Changing the port means changing the published port too. |
| `invisible_proxy` | off | Accept origin-form requests from non-proxy-aware clients. |
| `invisible_tls_enabled` / `invisible_tls_port` *(system only)* | off / `9444` | SNI-based listener for redirected HTTPS. |
| `invisible_default_host` | — | Fallback target when a request has no `Host` header. |
| `intercept_enabled` | off | Master interception switch. |
| `intercept_requests` / `intercept_responses` | on / off | Which directions are held. |
| `intercept_skip_extensions` | css, js, images, fonts… | Never held, even in scope. |
| `scope_include` / `scope_exclude` | empty | Regexes against the full URL. |
| `header_rules` | empty | Header rewrites applied to proxied traffic. |
| `listen_http2` *(system only)* | on | Advertise `h2` to clients in ALPN. |
| `upstream_http2` | on | Offer `h2` to origin servers. |
| `upstream_proxy` | — | Chain to another proxy, e.g. `http://corp-proxy:3128`. |
| `upstream_verify_tls` | off | Off lets you test hosts with bad certificates. |
| `connect_timeout` / `read_timeout` | 10s / 30s | Upstream timeouts. |
| `tls_passthrough_hosts` | empty | Tunnelled undecrypted. `*.example.com` matches subdomains. |
| `vpn_required` *(system only)* | off | Kill switch: refuse to send anything while the tunnel is down. |
| `vpn_autoconnect` *(system only)* | — | Profile id to connect at start-up. |
| `vpn_override_dns` *(system only)* | on | Point `/etc/resolv.conf` at the tunnel's DNS. |
| `vpn_exit_ip_url` *(system only)* | `https://api.ipify.org` | Used by "Check exit IP". |
| `logging_enabled` / `log_out_of_scope` | on / on | History logging. |
| `max_history` | 50000 | Older rows are trimmed periodically. |
| `max_stored_body` | 2 MiB | Stored response cap. The client still gets the full body. |

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `BRUP_DATA` | `brup-data` | Host location of the data: a named volume, or a path to bind-mount. Read by `docker compose`, not the application. |
| `BRUP_DATA_DIR` | `/data` | Where that data is mounted inside the container, and where the application looks for it. |
| `BRUP_BIND` | `0.0.0.0` | Host interface the ports are published on. Read by `docker compose`. |
| `BRUP_UI_BIND` | `$BRUP_BIND` | Overrides the above for the UI and API only. |
| `BRUP_LOG_LEVEL` | `INFO` | Python log level. `DEBUG` adds VPN client output. |

Set these in `.env` (start from `.env.example`).

## Development

Run the backend in the container and the Vite dev server on your host for hot
reload:

```bash
docker compose up -d              # backend on :9080, proxy on :9081
cd frontend && npm install && npm run dev
```

The dev server on <http://localhost:5173> proxies `/api` and `/ws` through to
`localhost:9080`.

Tests cover the proxy path end to end — absolute-form and invisible proxying,
CONNECT MITM against a real TLS server, intercept edit/drop, chunked decoding,
keep-alive, all four Intruder attack types, sitemap tree construction, project
isolation, settings inheritance, VPN config parsing and the kill switch, and
the API surface:

```bash
docker run --rm \
  -v "$PWD/backend/tests:/app/tests:ro" \
  -v "$PWD/backend/pytest.ini:/app/pytest.ini:ro" \
  brup:latest sh -c "pip install -q pytest pytest-asyncio httpx && python -m pytest -q"
# 173 passed
```

Layout:

```
backend/brup/
  main.py             FastAPI app, lifespan, static UI
  api/routes.py       HTTP API + WebSocket feed
  proxy/server.py     listeners, CONNECT/MITM, invisible mode, request lifecycle
  proxy/upstream.py   raw request → raw response (shared by proxy/repeater/intruder)
  proxy/interceptor.py  hold/forward/drop queue
  http_message.py     byte-level HTTP parsing
  ca.py               CA + on-demand leaf certificates
  projects.py         projects, active project, effective settings
  vpn.py              VPN profiles, tunnel lifecycle, kill switch
  http2.py            HTTP/2 message form, and translation to HTTP/1.1
  proxy/h2_server.py  serving h2 to a client, one task per stream
  proxy/h2_client.py  sending one h2 request upstream
  intruder.py         positions, payload sets, attack engine
  sitemap.py          host/path tree built from history rows
  db.py               SQLite storage
frontend/src/
  views/              Intercept, History, Settings, Sitemap, Repeater, Intruder
  components/Sidebar  project list, create/select/delete
  components/SettingsForm  both settings tiers, with override controls
  components/VpnCard  import, connect, kill switch, exit-IP check
  components/         RawEditor, MessageViewer, Split, PayloadSetEditor
  raw.ts              byte-safe raw ⇄ editor-text conversion
```

## Design notes and limits

**Raw bytes are preserved.** Requests are parsed at the byte level and header
order, header casing and odd whitespace all survive the round trip. Editor text
is treated as latin-1 — one character per byte — so nothing you type gets
silently rewritten. The proxy, Repeater and Intruder share one code path, so a
request behaves the same wherever you send it from.

Known limits:

- **No WebSocket interception.** A WebSocket upgrade is proxied but not decoded.
- **Chunked bodies are de-chunked** and re-framed with `Content-Length`. Good for
  editing, but it means request-smuggling tests that depend on exact chunked
  framing are out of scope.
- **One upstream connection per request.** Simple and predictable; slower than a
  pooling proxy under heavy Intruder load.
- **No authentication on the UI.** Anyone who can reach port 9080 controls the
  proxy and can read every project's history. Set `BRUP_UI_BIND=127.0.0.1` to
  keep it on localhost; do not publish it to a network you do not control.
- **Projects are an organisational boundary, not a security one.** They live in
  one SQLite database and anyone with UI access can switch between them.
- **Response interception is off by default** — turning it on halts every
  matching response, which is rarely what you want while browsing.

## Authorised use

This is a penetration-testing tool. Intercepting traffic and running Intruder
against a system you do not own or have written permission to test is likely
illegal. Intruder in particular sends a lot of traffic quickly — keep the
concurrency and total request count low enough that you do not take the target
down, and only ever point it at systems you are authorised to test.
