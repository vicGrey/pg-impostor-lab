<!--
Title: Why sslmode=require Isn't Enough: Testing PostgreSQL TLS Against Impostor Servers
Subtitle: Part 1 of the PostgreSQL TLS Identity Lab: A Local Docker Baseline
Tags: postgresql, security, tls, docker, devops
-->

Your application connects to PostgreSQL, and `psql` reports an encrypted session:

```text
psql (18.6 (Debian 18.6-3))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off, ALPN: postgresql)
Type "help" for help.
```

The traffic across the wire is encrypted. Passive eavesdroppers cannot inspect the packets. But is your application actually communicating with your database, or with a rogue server impersonating it?

In this post, I test four PostgreSQL server configurations on one machine—one legitimate instance and three impostors—and connect to each using [every `sslmode` that libpq supports](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNECT-SSLMODE). The test results reveal a critical distinction: only `sslmode=verify-full` detects and blocks all three impostors.

Everything in this guide is reproducible. You can inspect the scripts, configuration files, and raw terminal logs pinned in the [pg-impostor-lab repository](https://github.com/vicGrey/pg-impostor-lab/tree/phase-1) (tag: `phase-1`).

## TL;DR

- `sslmode=require` encrypts traffic, but without a root certificate, it accepts any certificate presented by any server.
- `sslmode=verify-ca` validates the Certificate Authority (CA) signature, but ignores the certificate's Subject Alternative Names (SANs). Any server with a certificate issued by that same CA can impersonate your database.
- `sslmode=verify-full` was the only mode that rejected every impostor.
- Setting `ssl = on` in `postgresql.conf` enables the TLS engine, but does not enforce it. You must configure [hostssl rules in pg_hba.conf](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html) to reject plaintext connections.
- Add `require_auth=scram-sha-256` and `channel_binding=require` to your client connection parameters to close authentication downgrade and relay vectors.

For production workloads, your base connection string should mirror this pattern:

```text
host=db.example.com dbname=app user=app sslmode=verify-full sslrootcert=/path/to/ca.crt require_auth=scram-sha-256 channel_binding=require
```

## Encryption Is Not Authentication

Transport Layer Security (TLS) provides two distinct guarantees that are often conflated:

- **Encryption (Confidentiality):** Scrambles data in transit so passive network observers cannot inspect its contents.
- **Identity Verification (Authentication):** Proves cryptographically that the remote endpoint receiving your data holds the identity your client intended to reach.

Encryption without identity verification is like handing a sealed envelope to whoever opens the door. People in the hallway cannot read your letter, but if you do not confirm the recipient's identity, you risk handing sensitive data directly to an impostor.

An attacker executing a Man-in-the-Middle (MitM) redirection does not need to break the cryptographic cipher. In practice, an attacker intercepts or redirects traffic to their rogue server via DNS spoofing, ARP poisoning, BGP route hijacking, or a misconfigured Kubernetes Service. They only need your client to establish a valid TLS handshake with their rogue server.

## What You Need

To follow this walkthrough, you need basic familiarity with the command line and the following tools. Versions are pinned to ensure reproducible handshakes and error messages:

| Component | Version | Role |
|---|---|---|
| Docker Engine | 24 or later | Runs the database containers |
| PostgreSQL Server | `postgres:18.6-alpine` | Runs the legitimate and impostor database instances |
| PostgreSQL Client | `psql` (libpq 18.6) | Executes host-side connection tests |
| OpenSSL | 3.6.3 | Generates Certificate Authorities and X.509 certificates |

Clone the lab repository:

```bash
git clone https://github.com/vicGrey/pg-impostor-lab.git
cd pg-impostor-lab
git checkout phase-1
```

The Alpine image is used for its minimal container footprint.

## Step 1: Build the Chain of Trust

Before enabling TLS on PostgreSQL, you need a Certificate Authority (CA) and a server certificate signed by that CA:

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
*Diagram: A two-tier public key infrastructure (PKI) hierarchy where a trusted Root CA (CA-A) signs the server certificate containing Subject Alternative Names for postgres-real, localhost, and 127.0.0.1.*

### Private Keys and Public Certificates

- **Private Key (`.key`):** The server's secret key. Anyone with access to this file can impersonate the server until the certificate expires or is revoked.
- **Certificate (`.crt`):** The server's public identity document, transmitted during every TLS handshake. It contains the server's public key, the hostnames and IP addresses it is valid for (its Subject Alternative Names, or SANs), and the issuing CA's digital signature.

### Why a Copied Certificate Is Not Enough

Because a server sends its public certificate to every connecting client, you might wonder what prevents an attacker from capturing that certificate and serving it from a rogue instance.

In TLS 1.3 ([RFC 8446, Section 4.4.3](https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3)):

1. The client and server exchange random nonces and ephemeral Diffie-Hellman key shares, establishing a handshake transcript unique to that specific connection.
2. The server signs a cryptographic hash of that entire handshake transcript using its private key, transmitting the result in a `CertificateVerify` message.
3. The client verifies that signature using the public key embedded in the server's certificate.

An impostor possessing only a copied certificate cannot generate a valid `CertificateVerify` signature without the corresponding private key. As a result, the handshake fails immediately.

Because an attacker cannot reuse the legitimate server's certificate without its private key, each impostor in this lab must generate its own key pair and certificate. The experiment tests which of those certificates your client accepts under each `sslmode`.

### Generate the CAs and Test Server Certificates

The lab creates two CAs and four server certificates:

| Target | Signed by | Names in the SAN | Test Purpose |
|---|---|---|---|
| `real` | CA-A (trusted) | `postgres-real`, `localhost`, `127.0.0.1` | The legitimate server |
| `impostor-wrong` | CA-B (untrusted) | `postgres-wrong` | Untrusted CA and wrong hostname |
| `impostor-correct` | CA-B (untrusted) | `postgres-real`, `localhost`, `127.0.0.1` | Untrusted CA, matching hostname |
| `impostor-sameca` | CA-A (trusted) | `postgres-wrong` | Trusted CA, wrong hostname |

The `impostor-sameca` target represents the most dangerous scenario: another internal service in your infrastructure that holds a valid certificate signed by your organization's shared internal CA.

The certificate generation script ([`./scripts/gen-certs.sh`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/scripts/gen-certs.sh)) creates the root authorities and signs each server certificate with Subject Alternative Names using OpenSSL:

```bash
# Example: Generating the trusted Root CA (CA-A)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout docker/certs/ca-a.key -out docker/certs/ca-a.crt \
  -days 365 -subj "/CN=Lab-Real-CA"

# Example: Generating the legitimate server certificate signed by CA-A with SANs
openssl req -newkey rsa:2048 -nodes \
  -keyout docker/certs/server-real.key -out docker/certs/server-real.csr \
  -subj "/CN=postgres-real" \
  -addext "subjectAltName=DNS:postgres-real,DNS:localhost,IP:127.0.0.1"

openssl x509 -req -in docker/certs/server-real.csr \
  -CA docker/certs/ca-a.crt -CAkey docker/certs/ca-a.key -CAcreateserial \
  -out docker/certs/server-real.crt -days 365 -copy_extensions copy
```

To generate all four server targets, run the complete script:

```bash
./scripts/gen-certs.sh
```

## Step 2: Start the Server. Does `ssl = on` Force Encryption?

A frequent configuration assumption is: *"I set `ssl = on` and mounted valid certificates, so all incoming connections are encrypted."*

To test this assumption, start PostgreSQL with TLS enabled while retaining the official Docker image's default `pg_hba.conf`, which accepts standard `host` connections.

Notice that the command mounts only the specific certificate and key required by this container, rather than mounting the entire `docker/certs` directory. This keeps the CA private key (`ca-a.key`) off the container's filesystem entirely.

Furthermore, the command binds port 5432 strictly to the local IPv4 and IPv6 loopback interfaces (`-p 127.0.0.1:5432:5432 -p '[::1]:5432:5432'`) rather than exposing the database across all host network interfaces:

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

Two security considerations in this command are critical:

1. **Least-Privilege Mounts:** Mounting only the two required files avoids exposing unrelated private keys to the container process. Adding the `:ro` flag ensures a compromised container cannot tamper with host-side certificates. Because file ownership cannot be modified inside a read-only mount, the entrypoint script copies the key to `/tmp`, reassigns ownership to the `postgres` user, and restricts permissions to `0600`.
2. **Key File Permission Enforcement:** PostgreSQL verifies file permissions during startup according to the [PostgreSQL SSL Server Certificate Security Rules](https://www.postgresql.org/docs/current/ssl-tcp.html#SSL-SERVER-CERT-SECURITY). The server refuses to boot if the private key is readable by other system users. The key must be owned by the `postgres` user with permissions `0600` (or owned by `root` with permissions `0640`). If permissions are set to `0644`, startup halts immediately:

```text
FATAL: private key file "/tmp/server.key" has group or world access
```

## Step 3: Test Every `sslmode` Against Every Server

Export the password so `psql` can connect non-interactively:

```bash
export PGPASSWORD=postgres
```

The test script [`./scripts/test-matrix.sh`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/scripts/test-matrix.sh) runs all six libpq connection modes against the target endpoint.

The script only connects to whatever server process is currently listening on port 5432; it does not manage or restart containers automatically. To test an impostor, recreate the container with that impostor's certificate and key, then pass its identifier as the first argument:

```bash
# 1. Test the real server
./scripts/test-matrix.sh real localhost 5432 docker/certs/ca-a.crt

# 2. Swap in an impostor container (repeat for impostor-wrong, impostor-correct, and impostor-sameca)
docker rm -f postgres-real

# Re-run docker run, mounting server-impostor-sameca.crt and server-impostor-sameca.key
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

In this lab setup, the impostor containers share the same password as the real database in order to isolate the mechanics of TLS identity verification. **Connected** means the client established an active session without validating the server's identity. In a real-world scenario, the rogue server would not possess your SCRAM verifier; as explored in the next section, an attacker would instead exploit the unverified tunnel to request a cleartext password, skip authentication, or relay the handshake. **Refused** means the client detected a verification failure and terminated the connection before sending credentials.

Because both loopback listeners are bound, clients resolving `localhost` will attempt IPv6 `::1` or IPv4 `127.0.0.1` depending on host resolver order; in my test environment, `localhost` connects to IPv6 `::1`.

| Target | Signed by | `require` (no CA) | `require` (with CA) | `verify-ca` | `verify-full` |
|---|---|---|---|---|---|
| `real` | CA-A (trusted) | Connected | Connected | Connected | Connected |
| `impostor-wrong` | CA-B (untrusted) | **Connected (vulnerable)** | Refused* | Refused | Refused |
| `impostor-correct` | CA-B (untrusted) | **Connected (vulnerable)** | Refused* | Refused | Refused |
| `impostor-sameca` | CA-A (trusted) | **Connected (vulnerable)** | **Connected (vulnerable)** | **Connected (vulnerable)** | Refused |

*\*Refused only because a root CA file was explicitly passed to libpq.*

Here is a breakdown of each mode's behavior.

### `sslmode=disable`: Plaintext, Even With `ssl = on`

```bash
psql "host=localhost port=5432 user=postgres dbname=postgres sslmode=disable" \
  -c "\conninfo" \
  -c "SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid();"
```

Evidence output from [`evidence/phase1/real-disable-without-root.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/real-disable-without-root.txt):

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

The session connected completely unencrypted.

This answers the question posed in Step 2: `ssl = on` activates the TLS engine, but does not mandate its use. Unless your `pg_hba.conf` uses [hostssl rules](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html), any client requesting a plaintext connection receives one, exposing queries and authentication exchanges. (Part 2 shows how the Percona Operator configures `hostssl` by default).

### The Plaintext Fallback Modes: `allow` and `prefer`

The three modes that permit unencrypted plaintext (`disable`, `allow`, and `prefer`) fail to guarantee encryption:

- **`sslmode=allow`:** Attempts a plaintext connection first, upgrading to TLS only if the server explicitly rejects unencrypted traffic. Because default `pg_hba.conf` rules permit plaintext, the session remains unencrypted ([`evidence/phase1/real-allow-without-root.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/real-allow-without-root.txt)).
- **`sslmode=prefer`:** Attempts TLS first, falling back to plaintext if TLS negotiation fails. This is libpq's default behavior when `sslmode` is omitted.

This silent fallback is a security risk. An active network adversary can force an unencrypted downgrade:

1. The client transmits an 8-byte `SSLRequest` packet.
2. The adversary intercepts the request.
3. The adversary returns a single byte containing `N` ("TLS unavailable").
4. The client accepts the response and continues in cleartext, exposing queries, data payloads, and passwords.

### `sslmode=require`: Encrypted, but Blind

The `require` setting eliminates plaintext downgrades: if the server refuses TLS, the client terminates the connection.

However, without a trusted root CA file, `require` does not validate the server's certificate. In the benchmark tests, it connected to every target:

- `impostor-wrong` (untrusted CA, invalid hostname)
- `impostor-correct` (untrusted CA, valid hostname)
- `impostor-sameca` (trusted CA, invalid hostname)

Documented, but easy to miss: as noted in the [PostgreSQL libpq SSL Mode Documentation](https://www.postgresql.org/docs/current/libpq-ssl.html#LIBPQ-SSL-SSLMODE-STATEMENTS), passing `sslrootcert` causes `require` to quietly validate the CA signature, matching the behavior of `verify-ca`. When `ca-a.crt` was present, `require` rejected both CA-B impostors:

```text
psql: error: connection to server at "localhost" (::1), port 5432 failed: SSL error: certificate verify failed
```

Relying on this behavior is fragile. If the root CA file is moved or omitted, `require` silently falls back to trusting any certificate.

### `sslmode=verify-ca`: Checks the Signature, Not the Name

The `verify-ca` setting requires TLS and validates that the server's certificate was signed by a trusted CA (`sslrootcert=docker/certs/ca-a.crt`).

Against both untrusted CA-B impostors, it terminates the connection securely. Output from [`evidence/phase1/impostor-wrong-verify-ca-with-root.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/impostor-wrong-verify-ca-with-root.txt):

```text
psql: error: connection to server at "localhost" (::1), port 5432 failed: SSL error: certificate verify failed
```

Next, test `verify-ca` against `impostor-sameca`, whose certificate was signed by the trusted CA-A, but issued for the Subject Alternative Name `postgres-wrong`:

```bash
psql "host=localhost port=5432 user=postgres dbname=postgres sslmode=verify-ca sslrootcert=docker/certs/ca-a.crt" -c "\conninfo"
```

Evidence output from [`evidence/phase1/impostor-sameca-verify-ca-with-root.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/impostor-sameca-verify-ca-with-root.txt):

```text
SSL Connection       | true
SSL Protocol         | TLSv1.3
SSL Cipher           | TLS_AES_256_GCM_SHA384
```

The client accepted the rogue server. The `verify-ca` mode validates the cryptographic signature of the issuing CA, but never verifies whether the hostname on the certificate matches the server you dialed.

This distinction explains why the [Google Cloud SQL documentation](https://docs.cloud.google.com/sql/docs/postgres/authorize-ssl) explicitly notes that `verify-ca` is sufficient only when each database instance has its own unique, dedicated server CA. In environments where an internal enterprise CA or Kubernetes cluster issuer issues certificates across multiple services, `verify-ca` leaves you vulnerable to any other service holding a valid certificate from that same CA.

### `sslmode=verify-full`: Complete Identity Verification

The `verify-full` mode enforces three distinct checks:

1. **Mandatory Encryption:** Disallows plaintext fallbacks.
2. **CA Validation:** Verifies that the certificate chains back to the trusted CA (`ca-a.crt`).
3. **Identity Verification:** Confirms that the host dialed by the client matches a name listed in the certificate's Subject Alternative Names (SANs).

When tested against `impostor-sameca`:

```bash
psql "host=localhost port=5432 user=postgres dbname=postgres sslmode=verify-full sslrootcert=docker/certs/ca-a.crt" -c "\conninfo"
```

Evidence output from [`evidence/phase1/impostor-sameca-verify-full-with-root.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/impostor-sameca-verify-full-with-root.txt):

```text
psql: error: connection to server at "localhost" (::1), port 5432 failed: server certificate for "postgres-wrong" does not match host name "localhost"
```

The connection failed as intended. While the certificate was issued by the trusted CA, `verify-full` detected the hostname mismatch (`postgres-wrong` vs. `localhost`) and aborted the session before transmitting credentials.

Against the legitimate server, where both the CA signature and the hostname match:

```bash
psql "host=localhost port=5432 user=postgres dbname=postgres sslmode=verify-full sslrootcert=docker/certs/ca-a.crt" -c "\conninfo"
```

Evidence output from [`evidence/phase1/real-verify-full-with-root.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/real-verify-full-with-root.txt):

```text
SSL Connection       | true
SSL Library          | OpenSSL
SSL Protocol         | TLSv1.3
SSL Key Bits         | 256
SSL Cipher           | TLS_AES_256_GCM_SHA384
SSL Compression      | false
ALPN                 | postgresql
```

## Beyond the Certificate: Lock Down Authentication

Establishing `sslmode=verify-full` ensures your application connects to the legitimate server. However, client-side authentication controls are necessary if an attacker gains control of your network path or attempts an authentication downgrade.

Since PostgreSQL 14, [password_encryption defaults to scram-sha-256](https://www.postgresql.org/docs/current/runtime-config-connection.html#GUC-PASSWORD-ENCRYPTION). SCRAM ([RFC 5802](https://datatracker.ietf.org/doc/html/rfc5802)) ensures that raw passwords and reusable password hashes are never sent over the wire during standard authentication. However, this protection assumes the server adheres to the protocol rules—and the server controls which authentication method to request.

If an impostor intercepts a client connection that does not enforce `verify-full`, it can exploit several downgrade vectors:

- **Cleartext Password Requests:** The rogue server can return an `AuthenticationCleartextPassword` challenge. By default, libpq responds by transmitting your raw database password inside the TLS tunnel.
- **Bypassing Authentication:** The rogue server can return `AuthenticationOk` immediately, accepting the session without credentials and logging every SQL statement and data payload your application sends.
- **Relaying SCRAM Exchanges:** As discussed in [RFC 5802 Section 9](https://datatracker.ietf.org/doc/html/rfc5802#section-9) (Security Considerations), an active MitM attacker could attempt to proxy authentication challenges between the client and the real database in real time to establish an authorized session.

Two client parameters close these vectors:

- **[`require_auth=scram-sha-256`](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNECT-REQUIRE-AUTH)** (available in libpq 16 and later): Instructs the client to reject any authentication challenge other than SCRAM-SHA-256.

You can test this defense by starting a server configured for cleartext authentication (`pg_hba.conf` method `password`):

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

libpq terminates the connection immediately before transmitting the password ([`evidence/phase1/require-auth-cleartext-downgrade.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/require-auth-cleartext-downgrade.txt)):

```text
psql: error: connection to server at "localhost" (::1), port 5432 failed: authentication method requirement "scram-sha-256" failed: server requested a cleartext password
```

Similarly, if a rogue server attempts to bypass credentials entirely, libpq aborts. To reproduce this, run `docker rm -f pg-cleartext`, start the same container again with `POSTGRES_HOST_AUTH_METHOD=trust` instead of `password`, wait for it to accept connections, and rerun the same `psql` command ([`evidence/phase1/require-auth-trust-bypass.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/require-auth-trust-bypass.txt)):

```text
psql: error: connection to server at "localhost" (::1), port 5432 failed: authentication method requirement "scram-sha-256" failed: server did not complete authentication
```

- **[`channel_binding=require`](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNECT-CHANNEL-BINDING):** Forces `SCRAM-SHA-256-PLUS` ([RFC 7677](https://datatracker.ietf.org/doc/html/rfc7677)). As defined in [RFC 5929](https://datatracker.ietf.org/doc/html/rfc5929), PostgreSQL uses `tls-server-end-point` channel binding, which cryptographically binds the authentication payload to the hash of the server's TLS certificate. Per the specifications (not tested in this lab), an attacker attempting to relay authentication between two different TLS connections cannot complete the handshake because the outer certificate hashes do not match.

For this test, remove the `pg-cleartext` container and restart the real server with the Step 2 `docker run` command, since the cleartext server has no TLS:

```bash
docker rm -f pg-cleartext

# Re-run the Step 2 docker run command (server-real.crt and server-real.key)
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

Connecting with both parameters active confirms that libpq negotiates SCRAM with channel binding ([`evidence/phase1/require-auth-scram.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/require-auth-scram.txt)):

```bash
psql "host=localhost port=5432 user=postgres dbname=postgres sslmode=verify-full sslrootcert=docker/certs/ca-a.crt require_auth=scram-sha-256 channel_binding=require" -c "\conninfo"
```

```text
SSL Connection       | true
SSL Protocol         | TLSv1.3
SSL Cipher           | TLS_AES_256_GCM_SHA384
ALPN                 | postgresql
```

If your database uses a certificate signed by a public CA—as some managed cloud database offerings like Neon do (which uses Let's Encrypt), in contrast to providers like AWS RDS, Google Cloud SQL, and Supabase, which require downloading custom CA certificates—set [`sslrootcert=system`](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNECT-SSLROOTCERT) (available in libpq 16 and later). This parameter directs libpq to use the operating system's default trust store and defaults to `sslmode=verify-full`. Furthermore, libpq actively rejects weaker modes when `sslrootcert=system` is configured ([`evidence/phase1/system-ca-weak-sslmode.txt`](https://github.com/vicGrey/pg-impostor-lab/blob/phase-1/evidence/phase1/system-ca-weak-sslmode.txt)):

```text
psql: error: weak sslmode "require" may not be used with sslrootcert=system (use "verify-full")
```

## Conclusion

Securing database connectivity requires treating confidentiality and authentication as two independent requirements. Configuring `ssl = on` on your database server and setting `sslmode=require` on your client establishes an encrypted transport tunnel, but it leaves your application completely blind to the identity of the remote host.

As the experimental evidence shows, modes that permit plaintext (`disable`, `allow`, `prefer`), `require` without a trusted CA, and `verify-ca` all fail to protect against rogue endpoints holding certificates issued by a shared internal CA. Enforcing `sslmode=verify-full` alongside modern authentication constraints is the only connection mode that validates server identity and closes the hostname gap.

### Key Takeaways

- **Encryption Does Not Equal Authentication:** `sslmode=require` prevents passive packet inspection, but accepts connections from rogue servers.
- **`ssl = on` Does Not Mandate TLS:** You must define explicit `hostssl` rules in `pg_hba.conf` to block unencrypted plaintext sessions.
- **`verify-ca` Leaves a Hostname Blind Spot:** In environments with shared CAs, any workload possessing a valid certificate can impersonate your database under `verify-ca`.
- **Enforce `sslmode=verify-full`:** This is the only mode that verifies both the issuing authority and the server's Subject Alternative Names.
- **Harden Client Authentication:** Combine `verify-full` with `require_auth=scram-sha-256` and `channel_binding=require` to close credential downgrade and relay vectors.

## What's Next: Kubernetes

On a single local machine using Docker, configuring `verify-full` successfully stopped every rogue endpoint. However, production environments introduce additional architectural complexity.

In Part 2, I deploy the Percona Operator for PostgreSQL 3.1.0 on Kubernetes (Civo) to investigate:

- The security implications of microservices sharing a common CA within the same namespace.
- Why operator-generated certificates fail `verify-full` when accessed over local port-forwarding or custom DNS domains (Percona Operator upstream issue [#1811](https://github.com/percona/percona-postgresql-operator/issues/1811)).
- The attack surface created when an operator stores the root CA's private key (`root.key`) in a standard Kubernetes Secret, allowing anyone with namespace read permissions to mint valid certificates that bypass `verify-full`.

In the meantime, you can replicate every test in this article locally. All test scripts, Docker configurations, and raw connection logs are available in the [pg-impostor-lab repository](https://github.com/vicGrey/pg-impostor-lab/tree/phase-1) (pinned tag: `phase-1`).
