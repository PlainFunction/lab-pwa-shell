import { z } from 'zod'
import { LocalToolServer, out, tool, ui, type AppToolsContext } from '#capabilities'

// The automations in this lab's app, for a made-up business, Harbour Plumbing.
// They're ordinary tools, the same contract the Slack agent uses, so a real
// client's would look the same: read their job system, chase a quote, tell
// their phone something. Nothing here reaches a real system or emails anyone.
// Which roles see which of these is in roles.ts.

const TIME_ZONE = 'Australia/Sydney'

const JOBS = [
  { at: '7:30am', what: 'Blocked drain', where: 'Marrickville', worth: 280 },
  { at: '10:00am', what: 'Hot water service, quote', where: 'Dulwich Hill', worth: 0 },
  { at: '1:30pm', what: 'Leaking tap', where: 'Petersham', worth: 150 },
]

const dollars = (n: number) => `$${n.toLocaleString('en-AU', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`

export const jobTools = () => new LocalToolServer('jobs', {
  today: tool({
    title: "Today's jobs",
    description: "What's booked in for today",
    input: z.object({}),
    output: z.object({
      day: out.header('Today'),
      jobs: out.list('Booked'),
      booked: out.field('Worth today').optional(),
      source: out.context('Where this comes from'),
    }),
    annotations: { readOnlyHint: true },
    // Everyone with this tool sees the run sheet. Only roles with see:prices see what the day is worth.
    run: (_input, ctx) => {
      const prices = ctx.can?.('see:prices') ?? false
      return {
        day: ctx.now.toLocaleDateString('en-AU', { timeZone: TIME_ZONE, weekday: 'long', day: 'numeric', month: 'long' }),
        jobs: JOBS.map(j => ({ title: j.what, detail: prices && j.worth ? `${j.where}, ${dollars(j.worth)}` : j.where, meta: j.at })),
        ...(prices ? { booked: dollars(JOBS.reduce((sum, j) => sum + j.worth, 0)) } : {}),
        source: 'Sample jobs. A real one reads the job system, like ServiceM8.',
      }
    },
  }),
}, { use: "Showing today's jobs", personalInfo: [], storesIn: 'Nowhere' })

export const quoteTools = () => new LocalToolServer('quotes', {
  follow_up: tool({
    title: 'Follow up a quote',
    description: "Sends a customer a friendly nudge about a quote they haven't answered",
    input: z.object({
      customer: ui.text('Customer'),
      email: ui.email('Their email'),
      quote: ui.text('Quote number', { description: 'As it appears on the quote, like Q-1042' }),
      amount: ui.number('Quote total ($)'),
      note: ui.text('Anything to add', { multiline: true }).optional(),
    }),
    output: z.object({
      done: out.header('Follow-up'),
      to: out.field('To'),
      quote: out.field('Quote'),
      lab: out.context('In this lab'),
    }),
    // Not read-only: it reaches a customer, so the app asks for a passkey first.
    run: ({ customer, email, quote, amount }) => ({
      done: `Ready to send to ${customer}`,
      to: email,
      quote: `${quote}, ${dollars(amount)}`,
      lab: 'Nothing was emailed. A real one hands this to the mailer once approved.',
    }),
  }),
}, { use: 'Chasing quotes', personalInfo: ['name', 'email'], checkedBy: 'Approved with a passkey before it runs', storesIn: 'Nowhere' })

const AUDIENCE = { Everyone: undefined, Office: ['office'], Tradies: ['tradie'] } as const

export const noticeTools = (notify: AppToolsContext['notify']) => new LocalToolServer('notify', {
  test: tool({
    title: 'Send a test notification',
    description: 'Sends a notification to everyone, or to one role',
    input: z.object({ message: ui.text('Message'), to: ui.select('Send to', ['Everyone', 'Office', 'Tradies']) }),
    output: z.object({ sent: out.field('Sent') }),
    run: async ({ message, to }) => {
      const roles = AUDIENCE[to]
      await notify({ title: 'Harbour Plumbing', body: message, url: '/', tag: 'test' }, roles && { roles: [...roles] })
      return { sent: to === 'Everyone' ? 'To every device with notifications on' : `To the ${to.toLowerCase()} devices with notifications on` }
    },
  }),
}, { use: 'Testing notifications', personalInfo: [], storesIn: 'Nowhere' })

export const tools = ({ notify }: AppToolsContext) => [jobTools(), quoteTools(), noticeTools(notify)]
