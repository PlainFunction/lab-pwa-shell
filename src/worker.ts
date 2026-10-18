import { createPwaShell } from '#capabilities'
import { roles } from './roles'
import type { LabEnv } from './scanning'
import { tools } from './tools'

// The whole Worker. The shell in dist/ is static assets; this answers /api/*.
export default createPwaShell<LabEnv>({ tools, roles })
