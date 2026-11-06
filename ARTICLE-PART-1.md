<!--
Title: Why sslmode=require Isn't Enough: Testing PostgreSQL TLS Against Impostor Servers
Subtitle: Part 1 of the PostgreSQL TLS Identity Lab: A Local Docker Baseline
Tags: postgresql, security, tls, docker, devops
-->

You've probably seen this line a hundred times and moved on:

```text
psql (18.6 (Debian 18.6-3))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off, ALPN: postgresql)
Type "help" for help.
```

It looks like the job is done. Your traffic is encrypted, and nobody sniffing the network can read your queries. But that line answers only one question: *is this connection private?* It says nothing about the more important one: *is this actually my database?*

In this article, you'll run one legitimate PostgreSQL server and three impostors on your own machine, then connect to each using [every `sslmode` libpq supports](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNECT-SSLMODE). By the end, you'll see why only `sslmode=verify-full` blocks all three impostors, and which two extra client parameters close the authentication gaps that remain.

Everything here is reproducible. The scripts, configuration, and raw terminal logs live in the [pg-impostor-lab repository](https://github.com/vicGrey/pg-impostor-lab/tree/phase-1) (tag: `phase-1`).

## TL;DR

- `sslmode=require` encrypts traffic, but without a root certificate, it accepts any certificate from any server.
- `sslmode=verify-ca` checks that a trusted Certificate Authority (CA) signed the certificate, but ignores the hostname. Any service holding a certificate from that same CA can impersonate your database.
- `sslmode=verify-full` was the only mode that rejected every impostor.
- `ssl = on` in `postgresql.conf` enables TLS but doesn't enforce it. You need [`hostssl` rules in `pg_hba.conf`](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html) to reject plaintext.
- Add `require_auth=scram-sha-256` and `channel_binding=require` on the client to close authentication downgrade and relay paths.

For production, your connection string should look like this:

```text
host=db.example.com dbname=app user=app sslmode=verify-full sslrootcert=/path/to/ca.crt require_auth=scram-sha-256 channel_binding=require
```

## Encryption Is Not Authentication

Transport Layer Security (TLS) gives you two separate guarantees that are easy to blur together:

- **Encryption (confidentiality):** Data in transit is scrambled, so passive observers can't read it.
- **Identity verification (authentication):** The server proves cryptographically that it holds the identity your client meant to reach.

Encryption without identity verification is like handing a sealed envelope to whoever opens the door. People in the hallway can't read your letter, but if you never check who's standing there, you may hand it straight to the wrong person.

This is why a man-in-the-middle (MitM) attacker doesn't need to break any cipher. They only need to get your traffic to their server, through DNS spoofing, ARP poisoning, a BGP hijack, or a misconfigured Kubernetes Service, and then complete a perfectly valid TLS handshake with your client.

## What You Need

You'll need some comfort with the command line and the tools below. Versions are pinned so the handshakes and error messages match what you see here:

| Component | Version | Role |
|---|---|---|
| Docker Engine | 24 or later | Runs the database containers |
| PostgreSQL Server | `postgres:18.6-alpine` | Runs the legitimate and impostor instances |
| PostgreSQL Client | `psql` (libpq 18.6; 16 or later is required for `require_auth` and `sslrootcert=system`) | Runs host-side connection tests |
| OpenSSL | 3.6.3 | Generates the CAs and X.509 certificates |

Clone the lab repository:

```bash
git clone https://github.com/vicGrey/pg-impostor-lab.git
cd pg-impostor-lab
git checkout phase-1
```

The Alpine image keeps the containers small.

## Step 1: Build the Chain of Trust

Before you enable TLS on PostgreSQL, you need a CA and a server certificate signed by it:

```text
+--------------------------------------------------------+
|                    Trusted Root CA                     |
|          ca-a.key (private) | ca-a.crt (public)        |
+--------------------------------------------------------+
                            |
                            | Signed by CA-A
                            v
+--------------------------------------------------------+
|              PostgreSQL Server Credentials             |
|  server-real.key (private) | server-real.crt (public)  |
+--------------------------------------------------------+
```

*Diagram: A two-tier public key infrastructure (PKI) where the trusted root CA (CA-A) signs a server certificate whose Subject Alternative Names are postgres-real, localhost, and 127.0.0.1.*

### Private Keys and Public Certificates

- **Private key (`.key`):** The server's secret. Anyone holding it can impersonate the server until the certificate expires or is revoked.
- **Certificate (`.crt`):** The server's public ID card, sent during every TLS handshake. It holds the server's public key, the hostnames and IP addresses it's valid for (its Subject Alternative Names, or SANs), and the issuing CA's signature.

### Why a Copied Certificate Is Not Enough

Since the server hands its certificate to every client, you might wonder what stops an attacker from copying it and serving it from their own machine.

The answer is in the TLS 1.3 handshake ([RFC 8446, Section 4.4.3](https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3)):

1. The client and server exchange random nonces and ephemeral Diffie-Hellman key shares, producing a handshake transcript unique to that connection.
2. The server signs a hash of the whole transcript with its private key and sends it in a `CertificateVerify` message.
3. The client checks that signature against the public key in the server's certificate.

Without the private key, an impostor can't produce a valid `CertificateVerify` signature, so the handshake fails. That's why each impostor in this lab generates its own key pair and certificate. The real question is which of those certificates your client will accept.

### Generate the CAs and Test Server Certificates

The lab creates two CAs and four server certificates:

| Target | Signed by | Names in the SAN | Test Purpose |
|---|---|---|---|
| `real` | CA-A (trusted) | `postgres-real`, `localhost`, `127.0.0.1` | The legitimate server |
| `impostor-wrong` | CA-B (untrusted) | `postgres-wrong` | Untrusted CA and wrong hostname |
| `impostor-correct` | CA-B (untrusted) | `postgres-real`, `localhost`, `127.0.0.1` | Untrusted CA, matching hostname |
| `impostor-sameca` | CA-A (trusted) | `postgres-wrong` | Trusted CA, wrong hostname |

Pay attention to `impostor-sameca`. It stands in for the most realistic threat: another internal service that holds a perfectly valid certificate from your organization's shared internal CA.

The [`./scripts/gen-certs.sh`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/scripts/gen-certs.sh) script creates both root CAs and signs each server certificate with its SANs. Here's the core of it:

```bash
# Generate the trusted root CA (CA-A)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout docker/certs/ca-a.key -out docker/certs/ca-a.crt \
  -days 365 -subj "/CN=Lab-Real-CA"

# Generate the legitimate server certificate, signed by CA-A, with SANs
openssl req -newkey rsa:2048 -nodes \
  -keyout docker/certs/server-real.key -out docker/certs/server-real.csr \
  -subj "/CN=postgres-real" \
  -addext "subjectAltName=DNS:postgres-real,DNS:localhost,IP:127.0.0.1"

openssl x509 -req -in docker/certs/server-real.csr \
  -CA docker/certs/ca-a.crt -CAkey docker/certs/ca-a.key -CAcreateserial \
  -out docker/certs/server-real.crt -days 365 -copy_extensions copy
```

Run the full script to generate all four targets:

```bash
./scripts/gen-certs.sh
```

## Step 2: Start the Server. Does `ssl = on` Force Encryption?

A common assumption goes like this: *"I set `ssl = on` and mounted valid certificates, so every connection is encrypted."*

To test it, start PostgreSQL with TLS enabled but keep the official image's default `pg_hba.conf`, which accepts ordinary `host` connections.

The command mounts only the certificate and key this container needs, not the whole `docker/certs` directory, so the CA private key (`ca-a.key`) never touches the container. It also binds port 5432 only to the IPv4 and IPv6 loopback interfaces instead of every network interface on your host:

```bash
docker run -d --name postgres-real -p 127.0.0.1:5432:5432 -p '[::1]:5432:5432' \
  -e POSTGRES_PASSWORD=postgres \
  -v "$(pwd)/docker/certs/server-real.crt:/certs/server.crt:ro" \
  -v "$(pwd)/docker/certs/server-real.key:/certs/server.key:ro" \
  postgres:18.6-alpine \
  sh -c "cp /certs/server.key /tmp/server.key && \
         chown postgres:postgres /tmp/server.key && \
         chmod 600 /tmp/server.key && \
         exec docker-entrypoint.sh postgres \
           -c ssl=on \
           -c ssl_cert_file=/certs/server.crt \
           -c ssl_key_file=/tmp/server.key"
```

Two details in this command are worth understanding:

1. **Least-privilege, read-only mounts:** Mounting only two files keeps unrelated private keys away from the container, and `:ro` stops a compromised container from tampering with your host's certificates. Because you can't change ownership on a read-only mount, the entrypoint copies the key to `/tmp`, hands it to the `postgres` user, and sets its permissions to `0600`.
2. **Key permission checks:** PostgreSQL inspects the key's permissions at startup, following its [server certificate security rules](https://www.postgresql.org/docs/current/ssl-tcp.html#SSL-SERVER-CERT-SECURITY). The key must be owned by `postgres` with `0600`, or by `root` with `0640`. Anything looser, like `0644`, stops the server cold:

```text
FATAL: private key file "/tmp/server.key" has group or world access
```

## Step 3: Test Every `sslmode` Against Every Server

Export the password so `psql` can connect without prompting:

```bash
export PGPASSWORD=postgres
```

The [`./scripts/test-matrix.sh`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/scripts/test-matrix.sh) script runs all six libpq modes against the target, once without and once with a root CA file, and saves each raw output as evidence.

The script connects to whatever is listening on port 5432. It doesn't start or stop containers. To test an impostor, recreate the container with that impostor's certificate and key, then pass the impostor's name as the first argument:

```bash
# 1. Test the real server
./scripts/test-matrix.sh real localhost 5432 docker/certs/ca-a.crt

# 2. Swap in an impostor (repeat for impostor-wrong, impostor-correct, and impostor-sameca)
docker rm -f postgres-real

# The container keeps the name postgres-real on purpose: from the client's side, nothing looks different
docker run -d --name postgres-real -p 127.0.0.1:5432:5432 -p '[::1]:5432:5432' \
  -e POSTGRES_PASSWORD=postgres \
  -v "$(pwd)/docker/certs/server-impostor-sameca.crt:/certs/server.crt:ro" \
  -v "$(pwd)/docker/certs/server-impostor-sameca.key:/certs/server.key:ro" \
  postgres:18.6-alpine \
  sh -c "cp /certs/server.key /tmp/server.key && \
         chown postgres:postgres /tmp/server.key && \
         chmod 600 /tmp/server.key && \
         exec docker-entrypoint.sh postgres \
           -c ssl=on \
           -c ssl_cert_file=/certs/server.crt \
           -c ssl_key_file=/tmp/server.key"

# Wait until the server accepts connections
until pg_isready -h 127.0.0.1 -p 5432 -q; do sleep 1; done

./scripts/test-matrix.sh impostor-sameca localhost 5432 docker/certs/ca-a.crt
```

### Results

To isolate TLS identity checks, the impostors use the same password as the real database. In the table, **Connected** means the client opened a session; for an impostor, that means it trusted the wrong server. **Refused** means the client caught a verification failure and closed the connection before sending credentials.

In a real attack, the rogue server wouldn't have your SCRAM verifier. Instead, it would use the unverified tunnel to ask for a cleartext password, skip authentication, or relay the handshake, which you'll explore later in this article.

One more detail: with both loopback listeners bound, `localhost` resolves to `::1` or `127.0.0.1` depending on your resolver. In my environment, it resolved to `::1`, which is why the errors below show `(::1)`.

| Target | Signed by | `require` (no CA file) | `require` (with CA file) | `verify-ca` | `verify-full` |
|---|---|---|---|---|---|
| `real` | CA-A (trusted) | Connected | Connected | Connected | Connected |
| `impostor-wrong` | CA-B (untrusted) | **Connected (fooled)** | Refused* | Refused | Refused |
| `impostor-correct` | CA-B (untrusted) | **Connected (fooled)** | Refused* | Refused | Refused |
| `impostor-sameca` | CA-A (trusted) | **Connected (fooled)** | **Connected (fooled)** | **Connected (fooled)** | Refused |

*\*Refused only because a root CA file was passed to libpq.*

Here's what each mode did and why.

### `sslmode=disable`: Plaintext, Even With `ssl = on`

```bash
psql "host=localhost port=5432 user=postgres dbname=postgres sslmode=disable" \
  -c "\conninfo" \
  -c "SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid();"
```

Output from [`evidence/phase1/real-disable-without-root.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/real-disable-without-root.txt):

```text
Database             | postgres
Client User          | postgres
Host                 | localhost
SSL Connection       | false
 ssl | version | cipher
-----+---------+--------
 f   |         |
(1 row)
```

The session ran with no encryption at all.

That answers the question from Step 2: `ssl = on` turns TLS on, but doesn't require it. Unless `pg_hba.conf` uses [`hostssl` rules](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html), any client that asks for plaintext gets it, queries and authentication included. Part 2 shows how the Percona Operator sets up `hostssl` by default.

### The Plaintext Fallback Modes: `allow` and `prefer`

`disable`, `allow`, and `prefer` all permit plaintext, so none of them guarantees encryption:

- **`sslmode=allow`:** Tries plaintext first and upgrades to TLS only if the server rejects it. With the default `pg_hba.conf`, the session stays unencrypted ([`evidence/phase1/real-allow-without-root.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/real-allow-without-root.txt)).
- **`sslmode=prefer`:** Tries TLS first and falls back to plaintext if negotiation fails. This is libpq's default when you don't set `sslmode` at all.

That silent fallback is easy for an active attacker to abuse:

1. Your client sends an 8-byte `SSLRequest` packet.
2. The attacker intercepts it.
3. The attacker replies with a single byte, `N` ("TLS unavailable").
4. Your client accepts that and carries on in cleartext, exposing queries, data, and passwords.

### `sslmode=require`: Encrypted, but Blind

`require` closes the downgrade: if the server won't do TLS, the client hangs up.

But without a root CA file, `require` doesn't check the server's certificate at all. In this lab, it connected to every impostor:

- `impostor-wrong` (untrusted CA, wrong hostname)
- `impostor-correct` (untrusted CA, right hostname)
- `impostor-sameca` (trusted CA, wrong hostname)

There's a documented but easy-to-miss twist. According to the [libpq SSL mode documentation](https://www.postgresql.org/docs/current/libpq-ssl.html#LIBPQ-SSL-SSLMODE-STATEMENTS), if you pass `sslrootcert`, `require` quietly behaves like `verify-ca`. With `ca-a.crt` present, `require` rejected both CA-B impostors:

```text
psql: error: connection to server at "localhost" (::1), port 5432 failed: SSL error: certificate verify failed
```

Don't lean on this. If the CA file gets moved or dropped from a deployment, `require` goes back to trusting any certificate, and nothing warns you.

### `sslmode=verify-ca`: Checks the Signature, Not the Name

`verify-ca` requires TLS and checks that a trusted CA (`sslrootcert=docker/certs/ca-a.crt`) signed the server's certificate.

It refused both CA-B impostors. Output from [`evidence/phase1/impostor-wrong-verify-ca-with-root.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/impostor-wrong-verify-ca-with-root.txt):

```text
psql: error: connection to server at "localhost" (::1), port 5432 failed: SSL error: certificate verify failed
```

Now point it at `impostor-sameca`, whose certificate CA-A signed for the name `postgres-wrong`:

```bash
psql "host=localhost port=5432 user=postgres dbname=postgres sslmode=verify-ca sslrootcert=docker/certs/ca-a.crt" -c "\conninfo"
```

Output from [`evidence/phase1/impostor-sameca-verify-ca-with-root.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/impostor-sameca-verify-ca-with-root.txt):

```text
SSL Connection       | true
SSL Protocol         | TLSv1.3
SSL Cipher           | TLS_AES_256_GCM_SHA384
```

The client accepted the rogue server. `verify-ca` confirms who signed the certificate, but never asks whether the certificate belongs to the host you dialed.

That's why the [Google Cloud SQL documentation](https://docs.cloud.google.com/sql/docs/postgres/authorize-ssl) says `verify-ca` is enough only when each instance has its own dedicated server CA. If an internal enterprise CA or a Kubernetes cluster issuer signs certificates for many services, `verify-ca` lets any of them pose as your database.

### `sslmode=verify-full`: Complete Identity Verification

`verify-full` enforces three checks:

1. **Encryption is mandatory:** No plaintext fallback.
2. **The CA is trusted:** The certificate chains back to `ca-a.crt`.
3. **The name matches:** The host you dialed appears in the certificate's SANs.

Run it against `impostor-sameca`:

```bash
psql "host=localhost port=5432 user=postgres dbname=postgres sslmode=verify-full sslrootcert=docker/certs/ca-a.crt" -c "\conninfo"
```

Output from [`evidence/phase1/impostor-sameca-verify-full-with-root.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/impostor-sameca-verify-full-with-root.txt):

```text
psql: error: connection to server at "localhost" (::1), port 5432 failed: server certificate for "postgres-wrong" does not match host name "localhost"
```

That's exactly what you want. The trusted CA signed the certificate, but `verify-full` caught the name mismatch (`postgres-wrong` vs. `localhost`) and closed the connection before sending any credentials.

Against the legitimate server, where both the signature and the name check out:

```bash
psql "host=localhost port=5432 user=postgres dbname=postgres sslmode=verify-full sslrootcert=docker/certs/ca-a.crt" -c "\conninfo"
```

Output from [`evidence/phase1/real-verify-full-with-root.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/real-verify-full-with-root.txt):

```text
SSL Connection       | true
SSL Library          | OpenSSL
SSL Protocol         | TLSv1.3
SSL Key Bits         | 256
SSL Cipher           | TLS_AES_256_GCM_SHA384
SSL Compression      | false
ALPN                 | postgresql
```

Both verifying modes also fail safe. With no CA file configured, `verify-ca` and `verify-full` refused to connect with `root certificate file ... does not exist` instead of falling back to unverified encryption.

## Beyond the Certificate: Lock Down Authentication

`verify-full` makes sure you reach the right server. Client-side authentication settings protect you when something else goes wrong: a connection string that slips back to a weaker mode, or an attacker who tries to downgrade how you log in.

Since PostgreSQL 14, [`password_encryption` defaults to `scram-sha-256`](https://www.postgresql.org/docs/current/runtime-config-connection.html#GUC-PASSWORD-ENCRYPTION). SCRAM ([RFC 5802](https://datatracker.ietf.org/doc/html/rfc5802)) means neither your raw password nor a reusable hash crosses the wire. But the server decides which method to ask for, and SCRAM only helps if the server plays fair.

If an impostor gets hold of a connection that isn't using `verify-full`, it has several options:

- **Ask for a cleartext password:** The rogue server sends `AuthenticationCleartextPassword`. By default, libpq answers with your raw password inside the TLS tunnel.
- **Skip authentication:** The rogue server replies `AuthenticationOk` straight away, then logs every query and result your application sends.
- **Relay SCRAM:** As [RFC 5802, Section 9](https://datatracker.ietf.org/doc/html/rfc5802#section-9) describes, an active attacker can try to pass SCRAM messages between your client and the real database in real time to get an authorized session.

Two client parameters shut these down.

### `require_auth=scram-sha-256`

[`require_auth=scram-sha-256`](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNECT-REQUIRE-AUTH) (libpq 16 and later) tells the client to reject any authentication method other than SCRAM-SHA-256.

To see it work, start a server that asks for cleartext passwords (`pg_hba.conf` method `password`):

```bash
# Remove the impostor container left over from Step 3 (it holds the same ports)
docker rm -f postgres-real

docker run -d --name pg-cleartext -p 127.0.0.1:5432:5432 -p '[::1]:5432:5432' \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_HOST_AUTH_METHOD=password \
  postgres:18.6-alpine

# Wait until the server accepts connections
until pg_isready -h 127.0.0.1 -p 5432 -q; do sleep 1; done

PGPASSWORD=postgres psql "host=localhost port=5432 user=postgres dbname=postgres sslmode=disable require_auth=scram-sha-256" -c "\conninfo"
```

libpq hangs up before sending the password ([`evidence/phase1/require-auth-cleartext-downgrade.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/require-auth-cleartext-downgrade.txt)):

```text
psql: error: connection to server at "localhost" (::1), port 5432 failed: authentication method requirement "scram-sha-256" failed: server requested a cleartext password
```

It also catches a server that tries to skip authentication. Run `docker rm -f pg-cleartext`, start the same container with `POSTGRES_HOST_AUTH_METHOD=trust` instead of `password`, wait for it, and rerun the same `psql` command ([`evidence/phase1/require-auth-trust-bypass.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/require-auth-trust-bypass.txt)):

```text
psql: error: connection to server at "localhost" (::1), port 5432 failed: authentication method requirement "scram-sha-256" failed: server did not complete authentication
```

### `channel_binding=require`

[`channel_binding=require`](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNECT-CHANNEL-BINDING) forces `SCRAM-SHA-256-PLUS` ([RFC 7677](https://datatracker.ietf.org/doc/html/rfc7677)). PostgreSQL uses `tls-server-end-point` channel binding from [RFC 5929](https://datatracker.ietf.org/doc/html/rfc5929), which ties the SCRAM exchange to a hash of the server's TLS certificate. Per the specifications (this lab doesn't test it), a relay between two different TLS connections fails because the certificate hashes don't match.

The cleartext server has no TLS, so remove it and bring back the real server from Step 2:

```bash
docker rm -f pg-cleartext

# Re-run the Step 2 command (server-real.crt and server-real.key)
docker run -d --name postgres-real -p 127.0.0.1:5432:5432 -p '[::1]:5432:5432' \
  -e POSTGRES_PASSWORD=postgres \
  -v "$(pwd)/docker/certs/server-real.crt:/certs/server.crt:ro" \
  -v "$(pwd)/docker/certs/server-real.key:/certs/server.key:ro" \
  postgres:18.6-alpine \
  sh -c "cp /certs/server.key /tmp/server.key && \
         chown postgres:postgres /tmp/server.key && \
         chmod 600 /tmp/server.key && \
         exec docker-entrypoint.sh postgres \
           -c ssl=on \
           -c ssl_cert_file=/certs/server.crt \
           -c ssl_key_file=/tmp/server.key"

# Wait until the server accepts connections
until pg_isready -h 127.0.0.1 -p 5432 -q; do sleep 1; done
```

Connect with every protection on, and libpq negotiates SCRAM with channel binding ([`evidence/phase1/require-auth-scram.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/require-auth-scram.txt)):

```bash
psql "host=localhost port=5432 user=postgres dbname=postgres sslmode=verify-full sslrootcert=docker/certs/ca-a.crt require_auth=scram-sha-256 channel_binding=require" -c "\conninfo"
```

```text
SSL Connection       | true
SSL Protocol         | TLSv1.3
SSL Cipher           | TLS_AES_256_GCM_SHA384
ALPN                 | postgresql
```

### If Your Provider Uses a Public CA

Some managed databases, such as Neon, use certificates from a public CA. Others, like AWS RDS, Google Cloud SQL, and Supabase, ask you to download their CA certificate.

For the public-CA case, set [`sslrootcert=system`](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNECT-SSLROOTCERT) (libpq 16 and later). libpq then uses your operating system's trust store and defaults to `sslmode=verify-full`. It even refuses weaker modes ([`evidence/phase1/system-ca-weak-sslmode.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/system-ca-weak-sslmode.txt)):

```text
psql: error: weak sslmode "require" may not be used with sslrootcert=system (use "verify-full")
```

## Conclusion

A secure database connection needs two things: privacy and proof of identity. `ssl = on` and `sslmode=require` give you the first. In this lab, the plaintext-capable modes, `require` without a CA file, and `verify-ca` all let at least one impostor through. Only `sslmode=verify-full` checked both the issuer and the name and stopped every impostor. Pair it with `require_auth=scram-sha-256` and `channel_binding=require`, and enforce `hostssl` on the server, and you've closed the gaps this lab exposed.

There's one limit worth stating plainly: `verify-full` is only as strong as your CA's private key. Anyone who can sign a certificate from your CA with your database's hostname will pass every check above. Before you change anything, open your connection strings and look for `require` or `verify-ca`. That's where to start.

## What's Next: Kubernetes

On a single machine, `verify-full` stopped every impostor. Production adds more moving parts.

In Part 2, I deploy the Percona Operator for PostgreSQL 3.1.0 on Kubernetes (Civo) to look at:

- What happens when microservices in the same namespace share one CA.
- Why operator-generated certificates fail `verify-full` over local port-forwarding or custom DNS names (Percona Operator issue [#1811](https://github.com/percona/percona-postgresql-operator/issues/1811)).
- How storing the root CA's private key (`root.key`) in a regular Kubernetes Secret lets anyone with namespace read access mint certificates that pass `verify-full`.

Until then, you can rerun every test in this article yourself. The scripts, Docker configuration, and raw logs are in the [pg-impostor-lab repository](https://github.com/vicGrey/pg-impostor-lab/tree/phase-1) (tag: `phase-1`).
