# Open Blocklist

[![HCL Ambassador](https://img.shields.io/static/v1?label=HCL&message=Ambassador&color=006CB7&labelColor=DDDDDD&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMjYuMjQgODYuMjgiPjxkZWZzPjxzdHlsZT4uY2xzLTF7ZmlsbDojMDA2Y2I3O308L3N0eWxlPjwvZGVmcz48ZyBpZD0iTGF5ZXJfMiIgZGF0YS1uYW1lPSJMYXllciAyIj48ZyBpZD0iRWJlbmVfMSIgZGF0YS1uYW1lPSJFYmVuZSAxIj48cG9seWdvbiBjbGFzcz0iY2xzLTEiIHBvaW50cz0iMTI2LjI0IDQzLjE0IDkxLjY4IDQzLjE0IDcyLjIgODYuMjggMTA2Ljc2IDg2LjI4IDEyNi4yNCA0My4xNCIvPjxwb2x5Z29uIGNsYXNzPSJjbHMtMSIgcG9pbnRzPSIwIDQzLjE0IDM0LjU2IDQzLjE0IDU0LjA0IDg2LjI4IDE5LjQ4IDg2LjI4IDAgNDMuMTQiLz48cG9seWdvbiBjbGFzcz0iY2xzLTEiIHBvaW50cz0iNjMuMTIgMCA0My42NCA0My4xNCA2My4xMiA4Ni4yOCA4Mi42IDQzLjE0IDYzLjEyIDAiLz48L2c+PC9nPjwvc3ZnPg==)](https://www.hcl-software.com/about/hcl-ambassadors)
[![Nash!Com Blog](https://img.shields.io/badge/Blog-Nash!Com-blue)](https://blog.nashcom.de)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/nashcom/buil-test/blob/main/LICENSE)


**Open Blocklist** is a distributed IP reputation and blocklist platform providing **DNS blocklists (RBL/DNSBL)**, **reverse DNS responses**, and **high-performance HTTP APIs** for reputation lookups and authorization.

The system is designed for **high-throughput environments** and **modern container-based deployments**.
It combines **CoreDNS**, **etcd**, and the **Open Blocklist service** written in Go to provide scalable blocklist management and high-performance querying.
Open Blocklist can be used by **mail systems**, **security gateways**, **reverse proxies**, **firewalls**, and other **reputation or abuse detection services**.


# Use Cases

Open Blocklist can be used for:

* Mail server reputation checks
* DNS blocklists (RBL / DNSBL)
* Reverse DNS reputation responses (for example with NGINX `$remote_host`)
* Subrequest authentication (for example with NGINX passing `$remote_addr`)
* API-based reputation checks
* Security gateways and abuse detection systems
* Integration with intrusion detection tools such as **CrowdSec**


# Components

Open Blocklist consists of three containers.

| Container               | Purpose                                       |
| ----------------------- | --------------------------------------------- |
| **open-blocklist-main** | Blocklist API and lookup service              |
| **open-blocklist-dns**  | CoreDNS DNS blocklist and reverse DNS service |
| **open-blocklist-etcd** | Distributed key-value storage backend         |


# Architecture

## **[CoreDNS](https://coredns.io/)** Server

CoreDNS provides the DNS interface for the blocklist.
It implements the DNS blocklist functionality using a forwarder configuration to a small DNS server provided only for RBL and IN-ARPA queries.
An earlier version used built-in **etcd integration**.
This allows DNS queries to be answered directly from the blocklist entries stored in etcd.


## **[etcd](https://etcd.io/)** Backend Storage

**etcd** provides the distributed key-value storage used by the platform.

Blocklist entries are stored in etcd for:

* persistence
* synchronization between services
* integration with CoreDNS

The entries are stored in SkyDNS-compatible layout in order to allow integration with Etcd.


## **[Go](https://go.dev/)** Based Application

The Open Blocklist service is written in **Go**.
The application provides the glue between the components and exposes REST API endpoints.
It maintains an **in-memory copy of all blocklist entries** using a high-performance map to ensure extremely fast API lookups and updates.
In addition it provides a small DNS server written in Go provide RBL and IN-ARPA replies directly from an in memory map.

### Data Flow

1. At startup, all data is loaded from **etcd** into memory.
2. API lookups are served directly from the in-memory map for maximum performance.
3. Updates are applied in memory and persisted to **etcd**.
4. CoreDNS uses a forwarder configuration to send requests directly to a DNS server, which is hosted by the open-blocklist container.
5. A background process enforces expiration policies and removes expired entries from both memory and **etcd**.


```
                    +----------------------------------+
                    |        In-Memory Store           |
                    |    (shared fast lookup map)      |
                    +---------+-----------+------------+
                              |           |
                              |           |
        +---------------------+           +---------------------+
        |                                               |
        v                                               v
+---------------------------+               +---------------------------+
|   Lookup / Auth API       |               |   Block Management API    |
|        (port 8080)        |               |        (port 8090)        |
+-------------+-------------+               +-------------+-------------+
              |                                           |
              |                                           |
              +-------------------+-----------------------+
                                  |
                                  v
                             +----------+
                             |  etcd    |
                             | store    |
                             +----------+

                                  ^
                                  |
                    (load on startup + persist updates)
                                  |
                     +-----------------------------+
                     | Background Expiration Worker|
                     +-----------------------------+
                                  |
                                  v
                             (cleanup both)

   +------------------+       forward        +----------------------+
   |     CoreDNS      | -------------------> |   DNSBL Server       |
   |  (DNS frontend)  |                      | (open-blocklist)     |
   +--------+---------+                      +----------+-----------+
            |                                           |
            v                                           v
       DNS Clients                              Uses In-Memory Store
```

---

# Quick Start

The repository contains a **Docker Compose setup** to quickly start the service.

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

**Note:** Ports can be changed in the configuration if they are already in use.


# Building the Image

The project includes a `build.sh` script.
By default, an **Alpine-based image** is used.

```
./build.sh
```


# Functionality

## Blocking an IP

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


## Blocking a Network (CIDR)

Add a network range to the blocklist:

```bash
curl -X PUT localhost:8090/block-network/192.168.1.0/24
```

Add with expiration and source:

```bash
curl -X PUT "localhost:8090/block-network/10.0.0.0/8?duration=24h&source=manual"
```

IPv6 networks are supported the same way:

```bash
curl -X PUT "localhost:8090/block-network/2001:db8::/32?duration=12h"
```

Remove a network block:

```bash
curl -X DELETE localhost:8090/block-network/192.168.1.0/24
```

The host bits of the supplied address are masked automatically, so `192.168.1.55/24` is stored as `192.168.1.0/24`.


## HTTP Lookup API

Query the blocklist by IP address:

```bash
curl localhost:8080/lookup/1.2.3.4
```

Example response (exact IP match):

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

If the IP is not individually blocked but falls within a blocked network range, the lookup still returns blocked and includes the matching CIDR:

```json
{
  "blocked": true,
  "ip": "192.168.1.55",
  "matched_cidr": "192.168.1.0/24",
  "source": "manual",
  "remaining_duration": "23h59m12s",
  ...
}
```


## HTTP Metadata Headers

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

When the match is a CIDR network block, an additional header is returned:

```
X-Blocklist-Matched-CIDR: 192.168.1.0/24
```


## Authorization Endpoint

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


## DNS Blocklist (RBL)

Query the DNS blocklist:

```bash
dig @127.0.0.1 -p 55 4.3.2.1.open-blocklist.internal +short
```

Response:

```
127.0.0.2
```


## Reverse DNS Lookup

Blocked IPs can also be queried via reverse DNS.

```bash
dig @127.0.0.1 -p 55 -x 1.2.3.4 +short
```

Example response:

```
blocked.internal.
```


## IPv6 Support

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


# Troubleshooting


## Inspecting Stored Entries

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


## Watching Updates

You can watch blocklist changes in real time.

```bash
docker exec open-blocklist-etcd \
etcdctl watch /skydns/internal/open-blocklist --prefix
```

Network (CIDR) blocks are stored under a separate prefix:

```bash
docker exec open-blocklist-etcd \
etcdctl get /skydns/internal/open-blocklist-cidr --prefix
```

Example:

```
/skydns/internal/open-blocklist-cidr/192.168.1.0_24
{"v":1,"host":"127.0.0.2","ttl":120,"source":"manual","first_seen":1773602647,"expiration":0}
```
```

This streams updates whenever entries are created, modified, or deleted.
