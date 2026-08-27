# Running a node for free

`lofswap-testnet` is only as alive as the nodes on it. Wallets ask nodes for
balances and push transactions straight to them, so if nothing is reachable the
wallet shows *no peers reachable* and nothing can be sent. This page is about
getting at least one reachable node back, without paying for hosting.

## What a seed node has to be

- **Reachable from the internet on TCP port 6000.** The port is not
  configurable: nodes reject peers announced on any other port.
- **Running continuously.** A node that sleeps when idle is not a seed node.
- That is all. It does **not** have to mine. A node relays blocks, serves the
  chain and accepts transactions whether or not it is hashing.

Resource use is modest — a non-mining node is happy on 1 vCPU and 512 MB.
Mining is CPU-bound and will use every core you give it.

## Options that actually work

### 1. A machine you already own — free, no signup

The most honest free option. An old laptop, a desktop that stays on, or a
Raspberry Pi will do. The node asks your router for a port mapping over UPnP
on startup, which on most home routers is enough to make it reachable:

```bash
cargo build -r -p node-cli
./target/release/node-cli
```

Watch the startup lines. `UPnP port mapping successful` means the router opened
port 6000 for you. If it failed, forward TCP 6000 to the machine by hand in the
router's admin page, and check the result with `get-publicip` in the node's
prompt plus a port checker.

The catch is a dynamic IP: most home connections change address every few days,
which breaks anyone using you as a seed. A free dynamic-DNS name and a wallet
configured with that name works around it — wallets resolve host names, and so
does the node when reading `LOFSWAP_BOOTSTRAP`.

### 2. Oracle Cloud Always Free — free indefinitely, needs an account

Oracle's Always Free tier includes VMs that do not expire, with a public IPv4
address and unrestricted inbound TCP. Signing up needs a card for identity
verification; the Always Free shapes are not billed.

Create an Ubuntu VM, paste [`deploy/cloud-init.yaml`](../deploy/cloud-init.yaml)
into the cloud-init box, then **open the port in two places**:

1. the subnet's security list — add an ingress rule for TCP 6000 from
   `0.0.0.0/0`;
2. the VM's own firewall — Oracle images ship an iptables rule that rejects
   everything except SSH. The cloud-init file inserts an ACCEPT rule for 6000,
   but verify it survived a reboot with `sudo iptables -L INPUT -n`.

Their free allowance covers two small VMs, which is worth using: the wallet
defaults to requiring **two** peers to accept a transaction before calling it
sent. With a single seed node, users have to lower that in Settings.

### 3. Google Cloud free tier — same shape, one VM

One `e2-micro` in `us-west1`, `us-central1` or `us-east1` is always free, with
30 GB of disk and 1 GB/month of outbound traffic. Same recipe: create the VM
with the cloud-init file, then add a VPC firewall rule allowing TCP 6000.

Watch the egress allowance — a busy node serving chain data to many wallets can
exceed 1 GB in a month, and the overage is billed.

### 4. Any VM you already pay for

[`deploy/systemd/lofswap-node.service`](../deploy/systemd/lofswap-node.service)
runs the binary directly, and
[`deploy/docker-compose.yml`](../deploy/docker-compose.yml) runs it in a
container:

```bash
docker compose -f deploy/docker-compose.yml up -d
```

## Options that do not work

Worth stating plainly, because they are the obvious things to reach for:

- **Render, Koyeb, Vercel, Netlify, Deno Deploy free tiers.** They route HTTP
  only. The node speaks its own protocol over raw TCP, so there is no port for
  peers to reach — and Render's free web services sleep when idle anyway.
- **GitHub Actions.** No inbound connectivity (peers could never connect), a
  six-hour cap per job, and GitHub's Acceptable Use Policies prohibit
  cryptocurrency mining on their runners. Do not run a miner there.
- **Fly.io, for a free IPv4.** Fly does route raw TCP, but only to a dedicated
  IP, and a dedicated IPv4 is billed. A dedicated IPv6 is free and works for
  IPv6-capable peers only. [`deploy/fly.toml`](../deploy/fly.toml) is there if
  you want it with that caveat understood.

## Once a node is up

Announce it as `IP:6000` and point clients at it.

**Wallets** — Settings → Seed nodes, one `host:port` per line. Or start the
wallet with the environment variable:

```bash
LOFSWAP_BOOTSTRAP=203.0.113.10:6000 wallet-gui
```

**Other nodes** — the same variable, or `--peer`:

```bash
node-cli --peer 203.0.113.10:6000
LOFSWAP_BOOTSTRAP=203.0.113.10:6000,203.0.113.11:6000 node-cli
```

Host names are resolved to addresses at startup, so a dynamic-DNS name works.

**Future releases** — update `DEFAULT_BOOTSTRAP_NODES` in
[`node-cli/src/main.rs`](../node-cli/src/main.rs) and `BOOTSTRAP_NODES` in
[`wallet-gui/src/net.rs`](../wallet-gui/src/net.rs) so new installs find the
network without being configured first.

## Checking that it is really reachable

From another machine:

```bash
printf '/ping' | nc <IP> 6000     # expect: pong
printf '/whoami' | nc <IP> 6000   # node id, version, chain id, peer count
```

If `/ping` answers locally but not remotely, the port is blocked somewhere
between — provider firewall, host firewall, or the router.

## Mining

A seed node does not need to mine, but somebody has to, or no blocks are
produced and transactions never confirm. Add a reward address:

```bash
node-cli --miner LFS...
```

Difficulty retargets towards one block a minute, so a single machine will
settle at whatever difficulty gives it roughly that rate. Proof of work runs on
its own thread and does not stop the node answering peers while it hashes.
