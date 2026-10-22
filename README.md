[![Built with TideCloak](https://tide.org/badges/built-with-tidecloak.svg)](https://tide.org/tidecloak?utm_source=github&utm_medium=readme&utm_campaign=unlocked)

# Water Treatment Dashboard

## Project overview

**Water treatment plant controls where no single account, not even an admin's, can make a dangerous change.**

Built with [TideCloak](https://tide.org/tidecloak?utm_source=github&utm_medium=readme&utm_campaign=unlocked).

### 1. Vision & originality
A plant control dashboard where a dangerous command such as lye dosing, filter shutdown or bypass opening only becomes *executable* once an AI risk check, the operator on shift and an independent engineer line up. Routine work stays one click.

### 2. Trust constraint insight
In Maroochy (2000), Ukraine (2015), Post Rock (2019), the widely reported Oldsmar incident (2021) and Aliquippa (2023), one insider, one stolen password or one default credential was enough to move physical equipment. Today a valid login *is* full authority, so utilities must either trust every account holder completely or ban the remote operation they depend on.

### 3. Value & impact
Towns get drinking water that cannot be poisoned through one compromised account. Utilities keep remote operations without betting public health on a single credential, and departed staff cannot come back in.

### 4. Why TideCloak matters
The PLC executes only commands carrying an authority signature over that exact command. The signature is produced only when the quorum policy is met. The app backend holds no key the PLC trusts, so a hacked server or admin cannot forge one. Role and policy changes need multiple admins. With ordinary login plus backend permissions, whoever controls the server controls the plant.

### 5. Prototype & storytelling
An attacker with Sam's stolen password sets NaOH to 11,100 ppm. The AI flags it as 111× normal, the Tide quorum withholds the signature, and Priya rejects it. A direct PLC call is refused, the compromised backend's forged approval is refused, and a stolen admin login cannot grant roles or lower the quorum alone.

---

## Architecture

```
 Browser (each person, own session)
   │  login / approve ──────────────────►  tide-sim :5000   (TideCloak + Tide network stand-in)
   │                                         • identity (signed session tokens)
   │                                         • quorum policy: operator + independent engineer if not routine
   │                                         • authority key: signs the exact command once the policy is met
   │                                         • governance: role/policy changes need 2 of 3 admins
   ▼
 app :3000  (dashboard backend: stores requests, relays signatures; holds NO authority key)
   │ relay
   ▼
 plc :4000  (mock controller: pins the Tide authority PUBLIC key; checks signature, digest,
             expiry, single use, and its own "dangerous ⇒ independent engineer" firmware floor)
```

The deterministic anomaly scorer ([shared/plant.js](shared/plant.js)) runs in all three places. The AI can raise risk but cannot lower it: the Tide policy and the PLC re-score the command themselves. Claude, if configured, only writes the explanation.

### TideCloak integration status
**The demo and video run on `tide-sim`, a local TideCloak simulator. Real TideCloak login, roles and admin change requests are coded (`TIDE_MODE=tidecloak`) but have not run live: Tide's licensing service failed when we set up the realm on 22 Oct 2026.**

| Piece | Demo (`TIDE_MODE=sim`, default) | Real TideCloak (`TIDE_MODE=tidecloak`, coded, not verified live) |
|---|---|---|
| Sign-in | `tide-sim` `POST /login` → signed token | Tide enclave login via `@tidecloak/js`; servers verify the EdDSA token against the realm key and its DPoP proof ([shared/tidecloak.js](shared/tidecloak.js)) |
| Roles | Live lookup in `tide-sim` | Realm roles `operator`, `engineer`, `admin`, read live from TideCloak by a read-only account |
| Role and policy changes | `tide-sim` change requests, 2 of 3 admins | TideCloak IGA change requests; each admin approves by signing in their own Tide enclave |
| Command authority | Gateway signs the exact command once the quorum is met; PLC pins its public key | Same (Fallback B). Tide-network signing needs a custom Forseti contract deployed by the Tide team |

## Setup

Requires Node 20+.

```bash
npm install
npm start          # starts tide-sim :5000, plc :4000, dashboard :3000
```

Open http://localhost:3000. Switch personas from the top bar, or open one tab per person with `?as=sam`, `?as=priya`, `?as=jordan` or `?as=attacker`. All passwords are synthetic (`demo`). Restart to reset the plant.

Optional: copy `.env.example` to `.env` and set `ANTHROPIC_API_KEY` to have Claude write the risk explanations.

```bash
npm test           # end-to-end: routine change, all three attacks, replay/tamper, 2-admin governance,
                   # plus the TideCloak token and DPoP verifier
```

Optional, real TideCloak (needs Docker): put `KC_BOOTSTRAP_ADMIN_PASSWORD`, `TIDE_LICENSE_EMAIL` and `TIDE_TERMS_ACCEPTED=yes` in `.env`, run `npm run tidecloak:bootstrap` (it starts TideCloak, creates the realm and prints one Tide invite link per persona), then set `TIDE_MODE=tidecloak` and `npm start`. Each person uses their own browser profile.

### Demo path (about 2 minutes)
1. **Sam**: use the preset "chlorine → 1.2" and submit. AI: LOW, and it executes instantly.
2. **Attacker** → ① Launch. NaOH 11,100 ppm is HIGH and held; self-approval and forcing it through are blocked.
3. **Priya**: the request is in her inbox. Click "Show what would have reached town", then **Reject**.
4. **Attacker** → ② "Call PLC directly" and "Compromised backend forges approval": both REJECTED.
5. **Attacker** → ③ Launch. Direct role grant is blocked; self-approval is blocked; requests are stuck at 1/2.
6. **Jordan**: reject Morgan's change requests.

## Sources
- Maroochy Shire (MITRE ATT&CK for ICS): https://attack.mitre.org/campaigns/C0020/
- Oldsmar: https://huntonak.com/privacy-and-information-security-law/florida-water-hack-shows-danger-of-remote-access-vulnerabilities
- Post Rock (US DOJ): https://www.justice.gov/usao-ks/pr/kansas-man-pleads-guilty-water-facility-tampering
- Aliquippa: https://www.secureworld.io/industry-news/iranian-hackers-target-us-water-facility
- Ukraine 2015: https://attack.mitre.org/campaigns/C0028/ and https://cisa.gov/news-events/ics-alerts/ir-alert-h-16-056-01
