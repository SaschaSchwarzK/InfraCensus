Core concept: Enrollment → short bootstrap secret → issued client cert → mTLS

1) Collector identity model

Each collector has:
	•	a Collector ID (UUID) + metadata (tenant, site/segment, labels, capabilities)
	•	a private key (generated locally in the collector; never leaves the host)
	•	a client certificate issued by your InfraCensus Collector CA

The central system stores:
	•	collector record (status, tenant binding, allowed scopes)
	•	certificate fingerprint / serial, validity, rotation history, last-seen, risk flags

2) Secure bootstrap (easy deployment)

You need one thing to bootstrap trust. Options (pick one, ordered by “most common in ops”):

A. One-time enrollment token (recommended)
	•	Admin creates a single-use enrollment token in the GUI/API for a specific tenant/site (TTL e.g. 10–30 minutes).
	•	Deploy collector container with ENROLLMENT_TOKEN=... (or mounted secret).
	•	Collector calls POST /collectors/enroll over TLS, presents token, sends a CSR (certificate signing request).
	•	Central verifies token → issues a client cert → token is immediately burned.


3) Steady-state auth: mTLS + scoped authorization

After enrollment:
	•	Every collector request uses mTLS (client cert auth at the reverse proxy / API gateway).
	•	Central maps cert → collector record → tenant + permissions.

Important: mTLS authenticates who the collector is. You still need authorization to limit what it can do:
	•	Collector can only fetch jobs for its tenant + its own collector ID.
	•	Collector can only upload results for jobs assigned to it.
	•	No “list all tenants”, no “get all credentials”, etc.

4) Prevent replay / abuse

Even with mTLS, add lightweight hardening:
	•	All job payloads include a job ID + expiration + nonce; collector must echo them back on result upload.
	•	Results uploads require the job to be assigned + not expired + not already completed.
	•	Rate-limit per collector ID; detect anomalies (new IP/ASN, geo changes, too many job polls, etc.).

5) Rotation & revocation
	•	Client cert lifetime: e.g. 7–30 days (short-lived is safer).
	•	Collector auto-renews using mTLS + “renew endpoint” before expiry.
	•	Central can revoke instantly by:
	•	marking collector disabled (authorization deny)
	•	adding cert serial/fingerprint to a CRL/OCSP (optional, depending on your TLS stack)

What the API should not do

To prevent “fake collectors fetching information”:
	•	Never allow bearer tokens that grant broad read access to collector job APIs.
	•	Never return shared secrets to collectors (collectors should receive job instructions, not global credentials; creds come from Vault at execution time or via centrally brokered access).
	•	Avoid “collector_id in header” as identity — identity must come from mTLS (the cert), not user-supplied fields.

Practical deployment UX (container friendly)

Admin workflow
	1.	Create Collector in GUI (tenant/site/capabilities).
	2.	Generate enrollment token (copy/paste).

Collector run
	•	docker run ... -e CENTRAL_URL=https://... -e ENROLLMENT_TOKEN=...
	•	Collector generates keypair, enrolls, stores cert/key in its local volume, then switches to mTLS mode.

Variants you might consider (depending on environment)
	•	SPIFFE/SPIRE: great if you want a standardized workload identity system for containers across environments.


turn this into:
	•	endpoint sketch (/enroll, /renew, /jobs/poll, /jobs/result)
	•	DB model fields for collectors + certs
	•	nginx/traefik config approach for enforcing mTLS at the edge.