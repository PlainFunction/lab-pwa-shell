# Lab 006: a private app on the phone, signed in with a passkey

The code behind our lab [A Private App on the Phone, No App Store](https://plainfunction.com.au/labs/pwa-shell).
It's an installable web app (a PWA) for one business. People sign in with a
passkey (Face ID, a fingerprint or the device PIN), run the business's
automations from simple forms, and approve anything that changes something
with another passkey tap. The passkey signs a hash of exactly what's about to
run. There are no passwords and no sign-in emails.

The app itself is our `pwa` capability. This lab is a Worker that uses it: a
config file, a few made-up automations for Harbour Plumbing, who can do what,
and scripts.

```ts
// src/worker.ts
export default createPwaShell({ tools, roles })

// src/tools.ts
export const tools = ({ notify }: AppToolsContext) => [jobTools(), quoteTools(), noticeTools(notify)]
```

```bash
npm install
npm test          # checks the capabilities copy, builds the shell within its size budget, runs the Worker's tests
npm run typecheck # the Worker, the page and the service worker
npm run dev       # builds the shell into dist/, then wrangler dev on http://localhost:8787
npm run dev:tunnel -- "Your name"   # the same, on a public https address for a phone, with an invite for it
```

## What it uses from capabilities

`capabilities/` holds copies of the parts of our capabilities it uses, so it
runs on its own. `capabilities/index.ts` says which parts, and
`scripts/sync-capabilities.mjs` keeps the copies in step with ours. **Don't
edit the copies**: they're overwritten from the source on every sync.

- `capabilities/core/pwa`: passkey checks (CBOR, COSE keys, signatures, all
  with Web Crypto), sessions, invites, approvals, the API, and the shell in
  `shell/` (page, script, styles, service worker, icons, build). Its
  `README.spec.md` has every port and adapter. Its own tests (over sixty, in
  workerd with real D1 and KV, and a software passkey) stay with the source.
- `capabilities/core/slack-agent/tools`: the tool contract. A tool written for
  our Slack agent shows up in this app as a form, and the other way round.
- `capabilities/core/channels/web-push.ts`: notifications, encrypted to the device.

## How it runs

```
Phone ──▶ Worker static assets (the shell: about 10 KB gzipped, cached by the service worker)
      ──▶ /api/* ──▶ Worker ──▶ D1 (people, passkeys, sessions, approvals) and KV (push subscriptions)
```

- **The shell is public and holds nothing private.** It's static assets, so
  loading it never runs the Worker (`run_worker_first = ["/api/*"]`).
  Everything a person sees after signing in comes from `/api/`, which needs a
  session, is never cached, and is never stored on the device.
- **No framework.** The page is one script of about 6 KB gzipped. It writes
  text with `textContent` only, and the CSP allows scripts from this site only.
- **One Worker per business**, with its own D1, KV and secrets.

## Setting it up

1. `npm run dev:secrets` writes `.dev.vars` with a `KEYRING` and a VAPID key
   pair for notifications. It never replaces a value that's there. Keep a copy
   of the keyring somewhere safe.
2. `npm run db:local` applies the schema to wrangler dev's local D1.
3. `npm run dev`, then in another terminal `npm run invite -- "Your name"`.
   Open the link it prints and press **Set up this device**.

To try it on a phone without deploying, install `cloudflared` and run
`npm run dev:tunnel -- "Your name"`. It opens a Cloudflare quick tunnel, starts
the Worker with the tunnel's address as `PUBLIC_URL` (passkeys only work at
the address they were made for), and prints an invite link for that address.
The address changes every run, so make a new invite each time.

To deploy:

1. `wrangler d1 create pwa-shell --location oc` and
   `wrangler kv namespace create pwa-shell`, and put the ids in `wrangler.toml`.
2. Set `PUBLIC_URL` to the address the app will keep. Passkeys are tied to its
   host name, so moving the app to a new address means everyone sets up again.
   Use a custom domain for a real business, not `workers.dev`.
3. `npm run db:remote`, then `wrangler secret put KEYRING --config wrangler.toml`
   and `wrangler secret put VAPID_PRIVATE_KEY --config wrangler.toml`, and put
   `VAPID_PUBLIC_KEY` in `wrangler.toml`'s vars.
4. `npm run deploy`, then `npm run invite -- "Their name" --remote`.

Invites from the script are Owners (role `admin`) unless you add
`--role office` or `--role tradie`. After the first one, people invite others
from the app's settings as their role allows, and anyone can add another of
their own devices there.

## Who can do what

`src/roles.ts` has Harbour Plumbing's roles. The Worker checks every request
against them; the app only hides what someone can't use.

| Role | Sees | Can |
|---|---|---|
| Owner (`admin`) | Every automation, with prices | Everything: invite anyone, change roles, recover and remove people |
| Office | Today's jobs and quote follow-ups, with prices | Invite tradies |
| Tradie | Today's jobs, without prices | Add their own devices |

A permission is `tool:<server>__<tool>` (with `*` as a wildcard), `people`,
`invite`, or one of the app's own like `see:prices`, which an automation
checks with `ctx.can?.('see:prices')`. Changing someone's role in Settings,
People applies from their next tap.

## Notifications

They're on by default: right after set-up the app asks once (phones only show
the prompt after a tap), and from then on every device that allowed them is
subscribed again whenever the app opens. Turning them off in Settings sticks
on that device. Each one shows the app's icon and name, with a white tick badge
in Android's status bar. Automations can send to everyone or to some roles:

```ts
await notify({ title: 'Harbour Plumbing', body: 'Mrs Nguyen said yes', url: '/' }, { roles: ['office'] })
```

## When someone loses their phone

- **Their passkey synced** (iCloud Keychain or Google Password Manager): the
  new phone already has it. They open the app and sign in.
- **They still have another device**: Settings, Add another device for the new
  one, then remove the lost one. It's signed out and stops getting
  notifications straight away.
- **They lost everything**: an owner opens Settings, People, and presses
  Recover access. That removes all their passkeys, signs them out everywhere,
  stops their notifications and cancels any links they hadn't used, then gives
  them a one-time link that sets up a new passkey on the same account, same role.
- **The last owner lost everything**: we do the same from here.

```bash
npm run invite -- --people --remote           # who's in, with their ids and roles
npm run invite -- --recover <id> --remote     # same as Recover access, minus the audit log entry
```

There's no email or SMS reset on purpose: it would be the easy way round the
passkeys for anyone pretending to be someone. The app tells people whose only
passkey is tied to one device to add a second one, so this is rare.

## Writing automations

An automation is a tool, the same as for our Slack agent: inputs are `ui.*`
fields, outputs are `out.*` fields (`out.list` for rows like jobs). Mark it
`readOnlyHint` if it only reads, and it runs straight away; with no inputs
too, it runs the moment it's tapped. Anything else asks for a passkey first.
Add it to the roles that should see it in `src/roles.ts`.

```ts
import { LocalToolServer, out, tool, ui } from '#capabilities'
import { z } from 'zod'

export const bookingTools = new LocalToolServer('bookings', {
  move: tool({
    title: 'Move a booking',
    description: 'Moves a job to another day and tells the customer',
    input: z.object({ job: ui.text('Job number'), day: ui.date('New day') }),
    output: z.object({ done: out.header('Moved'), when: out.field('New day') }),
    run: async ({ job, day }, ctx) => {
      // call the job system with ctx.fetch(url, { credential: 'servicem8' })
      return { done: `Job ${job} moved`, when: day }
    },
  }),
}, { use: 'Moving bookings', personalInfo: [], storesIn: 'The job system' })
```

The app can't draw Slack-only fields (`ui.user`, `ui.conversation`,
`ui.image`), so a tool that uses one is left out of the app and logged.

## Tested, and not yet tested

Run in Chrome (Playwright, with Chrome's virtual passkey authenticator)
against `wrangler dev`: the Owner, Office and Tradie each seeing their own
automations, prices only for the first two, changing a role from Settings,
the notifications prompt after set-up, a test notification arriving through
Google's push service with the icon and badge, recovering someone from the app (their browser
signed out, their old passkey refused) and from the script (their push
subscription gone from KV), the one-device warning, setting up from an invite, the invite leaving the
address bar, the home screen, a quote follow-up approved with the passkey,
signing out and back in with only the passkey, the service worker caching the
shell and nothing from `/api/`, Chrome offering to install it, turning on
notifications, and a notification sent through Google's real push service and
shown by the service worker. The security headers were checked on the real
asset responses.

Not yet run on a real phone: Face ID on an iPhone, Android's passkeys,
Windows Hello, or a notification through Apple's push service. The passkey
checks follow the WebAuthn spec and are tested against software passkeys, but
real authenticators can surprise.

## About this repo

This repo is synced automatically from another source, so it's read-only: pull requests and pushes aren't accepted here. If you spot a problem, tell us through [plainfunction.com.au/contact](https://plainfunction.com.au/contact).

Fork it and do what you like with it under the licence below.
