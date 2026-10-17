// A protected app for a client's phone and desktop: passkey sign-in, their
// automations as forms, approvals with a passkey tap, and notifications. The
// shell (shell/) is static assets; the Worker only answers /api/*. See README.spec.md.
//
//   import { createPwaShell } from '@plainfunction/capabilities/pwa'
//   export default createPwaShell({ tools: ({ env, notify }) => [myTools(env, notify)] })
//
// Not exported from core's index, like the Slack agent: it has its own entry point.

export { createPwaShell, createPwaWorker, json } from './worker'
export { PwaModule, RELYING_PARTY, APP_TOOL_SERVERS, APP_PUSH, relyingParty, type PwaEnv, type PwaOptions, type AppToolsContext } from './module'
export { Passkeys, Sessions, SESSION_COOKIE, deviceLabel, type SignedIn, type Person, type CreationOptionsJSON, type RequestOptionsJSON } from './auth'
export { Calls, type AppTool, type CallOutcome } from './calls'
export { Access, DEFAULT_ROLES, type Role, type Roles, type Abilities } from './roles'
export {
  AccountStore, D1AccountStore, SessionStore, D1SessionStore, ChallengeStore, D1ChallengeStore, PendingCallStore, D1PendingCallStore,
  type User, type Passkey, type Invite, type Session, type PendingCall, type CallStatus, type ChallengePurpose,
} from './stores'
export { fieldsOf, readForm, readField, shownOf, summaryOf, missing, SLACK_ONLY, UnsupportedField, type Field, type FieldKind, type Shown, type ShownItem } from './forms'
export {
  verifyRegistration, verifyAssertion, parseAuthData, importCoseKey, derToRaw, claimedChallenge, ALGORITHMS,
  type RelyingParty, type RegistrationJSON, type AssertionJSON, type VerifiedRegistration, type VerifiedAssertion,
} from './webauthn/webauthn'
export { decodeCbor, decodeCborAt, encodeCbor, type Cbor } from './webauthn/cbor'
export { SoftwarePasskey, type Bend } from './webauthn/software-passkey'

// Writing tools: the same contract as the Slack agent's.
export {
  ui, out, tool, LocalToolServer, ToolServer, needsAnswer, toJsonSchema,
  type ToolDef, type ToolContext, type CallContext, type ListItem, type ToolResult, type ToolSpec, type ToolAnnotations, type JsonSchema,
} from '../slack-agent/tools/contract'
export { serveMcp } from '../slack-agent/tools/mcp'
export type { Notice } from '../channels/channel'
