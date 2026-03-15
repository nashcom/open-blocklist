# Open Blocklist

**Open Blocklist** is a distributed IP reputation and blocklist platform providing **DNS blocklists (RBL/DNSBL)**, **reverse DNS responses**, and **high-performance HTTP APIs** for lookups and authorization.

The system is designed for high-throughput environments and modern container deployments.
It combines **CoreDNS**, **etcd**, and the **Open Blocklist service** to provide scalable blocklist management and querying.

Open Blocklist can be used by mail systems, security gateways, reverse proxies, firewalls, and reputation services.


# Use Cases

Open Blocklist can be used for:

- Mail server reputation checks
- DNS blocklists (RBL / DNSBL)
- Reverse DNS reputation responses - for example to use with NGINX `$remote_host`
- Sub request authentication requests - for example for NGINX passing the `remote_addr`)
- API-based reputation checks
- Security gateways
- Abuse detection systems
- Integration with intrusion detection tools such as CrowdSec


# Architecture

Open Blocklist runs as multiple cooperating services.

```
          +---------------------------+
          |   Block Management API    |
          |        (port 8090)        |
          +------------+--------------+
                       |
                       v
                   +-------+
                   | etcd  |
                   | store |
                   +---+---+
                       |
                       v
                 +-----------+
                 |  CoreDNS  |
                 |  DNSBL    |
                 +-----+-----+
                       |
                       v
                 DNS Clients

          +---------------------------+
          |   Lookup / Auth API       |
          |        (port 8080)        |
          +------------+--------------+
                       |
                       v
                      etcd
```

# Components

Open Blocklist consists of three containers.

| Container               | Purpose                                       |
| ----------------------- | --------------------------------------------- |
| **open-blocklist-main** | Blocklist API and lookup service              |
| **open-blocklist-dns**  | CoreDNS DNS blocklist and reverse DNS service |
| **open-blocklist-etcd** | Distributed key-value storage backend         |


# Quick Start

The repository contains a complete **Docker Compose setup**.

Start the system:

```bash
docker compose up -d
```

Example output:

```
[+] up 4/4
 ✔ Network open-blocklist_default Created
 ✔ Container open-blocklist-etcd  Started
 ✔ Container open-blocklist-dns   Started
 ✔ Container open-blocklist-main  Started
```


# Service Ports

| Service              | Port     | Purpose                            |
| -------------------- | -------- | ---------------------------------- |
| Lookup API           | **8080** | blocklist lookup and authorization |
| Block management API | **8090** | add/remove block entries           |
| DNS service          | **8053** | DNSBL and reverse DNS lookups      |

Example endpoints:

```
http://localhost:8080
http://localhost:8090
DNS: localhost:8053
```

**Note**: Ports can be changed in configuration if ports are already in use.


# How to build the image

The project comes with a build.sh script, which builds the image automatically.

```
./build.sh
```


# Blocking an IP

Add an IP address to the blocklist:

```bash
curl -X PUT localhost:8090/block/1.2.3.4
```

Add a block with expiration:

```bash
curl -X PUT "localhost:8090/block/1.2.3.4?duration=24h"
```

Add a block with a custom source:

```bash
curl -X PUT "localhost:8090/block/1.2.3.4?duration=2h&source=crowdsec"
```

Set a fixed expiration timestamp:

```bash
curl -X PUT "localhost:8090/block/1.2.3.4?expiration=2026-03-20T12:00:00Z"
```

Remove a block:

```bash
curl -X DELETE localhost:8090/block/1.2.3.4
```


# HTTP Lookup API

Query the blocklist:

```bash
curl localhost:8080/lookup/1.2.3.4
```

Example response:

```json
{
  "blocked": true,
  "expiration": 0,
  "expiration_iso": "",
  "first_seen": 1773602647,
  "first_seen_iso": "2026-03-15T19:24:07Z",
  "ip": "1.2.3.4",
  "remaining_duration": "permanent",
  "remaining_seconds": 0,
  "return_code": "127.0.0.2",
  "source": "open-blocklist"
}
```


# HTTP Metadata Headers

The lookup endpoint also returns useful metadata via HTTP headers.

```bash
curl -I localhost:8080/lookup/1.2.3.4
```

Example:

```
HTTP/1.1 200 OK
X-Blocklist-Status: blocked
X-Blocklist-Ip: 1.2.3.4
X-Blocklist-Return: 127.0.0.2
X-Blocklist-Source: open-blocklist
X-Blocklist-Remaining-Duration: permanent
```


# Authorization Endpoint

The `/auth` endpoint provides a fast allow/deny check.

Blocked address:

```bash
curl -I localhost:8080/auth/1.2.3.4
```

Response:

```
HTTP/1.1 403 Forbidden
```

Allowed address:

```bash
curl -I localhost:8080/auth/1.2.3.5
```

Response:

```
HTTP/1.1 204 No Content
```

This endpoint is useful for integration with reverse proxies or network gateways.


# DNS Blocklist (RBL)

Query the DNS blocklist:

```bash
dig @127.0.0.1 -p 55 4.3.2.1.open-blocklist.internal +short
```

Response:

```
127.0.0.2
```


# Reverse DNS Lookup

Blocked IPs can also be queried via reverse DNS.

```bash
dig @127.0.0.1 -p 55 -x 1.2.3.4 +short
```

Example response:

```
blocked.internal.
```


# IPv6 Support

IPv6 addresses can also be blocked.

```bash
curl -X PUT "localhost:8090/block/2001:db8::1?duration=24h"
```

Reverse lookup:

```bash
dig @127.0.0.1 -p 55 -x 2001:db8::1
```

Direct DNSBL query:

```
dig @127.0.0.1 -p 55 \
1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.open-blocklist.internal +short
```


# Inspecting Stored Entries

Blocklist entries are stored in etcd using a SkyDNS-compatible layout.

List entries:

```bash
docker exec open-blocklist-etcd \
etcdctl get /skydns/internal/open-blocklist --prefix
```

Example:

```
/skydns/internal/open-blocklist/1/2/3/4
{"v":1,"host":"127.0.0.2","ttl":300,"source":"open-blocklist","first_seen":1773602647,"expiration":0}
```


# Watching Updates

You can watch blocklist changes in real time.

```bash
docker exec open-blocklist-etcd \
etcdctl watch /skydns/internal/open-blocklist --prefix
```

This will stream updates whenever entries are created, modified, or deleted.

