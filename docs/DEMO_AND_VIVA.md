# Demonstration and individual viva guide

This is new preparation material. It does not certify that any student has
already performed the demonstration or passed an oral examination.

## Demonstration sequence

1. Inspect the existing VM state and private key configuration. Use the README's
   new private evidence directory and record owned process IDs.
2. Start topology first so the .254 management address exists; start OS-Ken with
   the private key and OpenFlow 6653; start auth .3:9000 and service .4:8080.
3. Show pingall and service self-access. Show h2 denial and inspect priority 100
   protected TCP drop/no matching priority 200 grant. Timeout alone is not proof.
4. From h1 log in. While the lease is active show the source .1/destination
   .4/TCP8080 priority 200 grant with finite hard timeout and application cookie.
   The expiry script's wait gives time for a second-terminal flow inspection.
5. Access the service, then logout. Show confirmed revoke, no matching grant,
   retained default deny and a healthy service that the client cannot reach.
6. Show automatic expiry and three-attempt lockout/recovery. Normal lease and
   lockout are 60 seconds; shorter test settings apply only to dedicated tests.
7. Show or explain a tested challenging scenario: unauthorized control requests,
   protected-service failure, or controller outage and recovery. A stopped
   service is an application failure, not a policy-enforcement success.
8. Explain current versus historical performance using the actual CSV and summary.
9. Stop only verified owned processes, exit Mininet and inspect final state.

Do not display session tokens or the private HMAC key. The application does not
print the session token during the ordinary client demonstration.

## Explanations every team member should prepare

| Question | Explanation |
|---|---|
|Why SDN?|Application authentication changes network forwarding policy dynamically through a controller.|
|Control/data planes?|Controller decisions and FlowMods are separate from OVS packet forwarding. Custom TCP9999 is distinct from OpenFlow6653.|
|Authentication/authorization?|Demo credentials establish identity; authorization is a temporary source-IP grant to .4:8080.|
|Priorities/cookie?|Priority200 grant overrides priority100 deny; priority0 NORMAL handles other traffic. Owned strict deletion preserves unrelated rules.|
|Barrier meaning?|A correlated barrier/error result confirms processing; real service access still needs a probe.|
|Token/session model?|Random token bound to observed IP, serialized transitions, expiry sweep, overlap lease restoration and retryable revoke failures. Same-IP users share access.|
|Replay protection?|HMAC covers canonical command/version/timestamp/connection nonce; a new challenge prevents reusing a captured envelope on another connection.|
|HMAC limits?|No encryption/TLS or signed ACK; VM administrator/key holders are trusted; source-IP/ARP spoofing assumptions remain.|
|Outage policy?|New logins fail. Existing finite grants can remain until hard timeout or later confirmed revoke. Restart loses in-memory auth sessions.|
|Protocol robustness?|One newline frame, byte cap, absolute receive deadline, strict JSON, handler caps and cleanup; not exhaustive DoS/fuzz assurance.|
|Fair performance comparison?|Compare service transaction times, keep all observations and disclose VM/order effects. Historical pre-HMAC results do not measure this candidate.|

Each student should independently perform login/access/logout, interpret a flow
dump, explain one failure/recovery case, and defend the baseline/limitations.
Record actual rehearsal outcomes; an automated passing suite is not viva proof.

The official supplied rubric requires final demonstration and individual viva,
but does not mandate slides or a particular diagram format. A visual topology
may be useful; the implemented four-host/one-switch arrangement is described in
README and topology.py.
