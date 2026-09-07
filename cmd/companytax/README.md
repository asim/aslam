# companytax

A standalone Go command that connects directly to Xero and prepares a local,
printable UK company tax working paper. No changes are made to Xero and nothing
is submitted to HMRC or Companies House. Uses only the Go standard library.

## Setup

From the repository root:

```sh
go build -o /tmp/companytax ./cmd/companytax
```

In [Xero My Apps](https://developer.xero.com/myapps), create an Auth Code/Web app
with redirect URI **http://localhost:5000/callback**. Enable these read scopes
in the app configuration (new apps use granular report scopes):

```
accounting.settings.read
accounting.reports.balancesheet.read
accounting.reports.profitandloss.read
accounting.reports.trialbalance.read
```

The login also requests `offline_access` for refresh tokens. Supply your app's
credentials through local environment variables `XERO_CLIENT_ID` and
`XERO_CLIENT_SECRET`. Do not commit credentials or generated accounting files.
Keep the variables available for later runs so the tool can refresh access.

```sh
/tmp/companytax login
/tmp/companytax tenants
/tmp/companytax init --config /tmp/micro-companytax.json
```

## Terminal review (recommended)

After login, run:

```sh
/tmp/companytax review --config /tmp/micro-companytax.json --data /tmp/micro-xero
/tmp/companytax generate --data /tmp/micro-xero --out /tmp/micro-return
```

`review` creates the company config if it does not exist. On the first run it
asks for the missing trading start and lets you select an authorised Xero
organisation, then downloads the reports. If `--data` already exists, it reviews
those saved reports offline; no Xero credentials are needed to resume.

The review asks for the UTR, confirms dates/reconciliation and tax scope, asks
about associated companies and any special cases, and records director/approval
details. It displays each period's P&L, asks which profit row to use and suggests
add-backs for positive depreciation or booked-tax rows. Suggestions are never
applied without confirmation. Other adjustments are entered with an amount and
reason; the tool does not infer capital-allowance eligibility from account names.

Each answer is saved immediately to `DATA/review.json` with owner-only
permissions and atomic replacement. Ctrl-C or end-of-input leaves completed
answers available for the next run. Existing answers are not asked again. Use
`--edit` to revisit them, or `--answers FILE` to keep a separate review. Conditional
answers (such as old director-loan details after changing the answer to no) are
excluded from generation. A lock prevents concurrent review/generation using
the same answers file.

The saved answers include a SHA-256 fingerprint of the downloaded evidence.
Changing any source report, company configuration or organisation data requires
a new review. To refresh from Xero, choose a new `--data` directory. Generation
validates all answers again and runs offline against that exact snapshot; it
refuses incomplete reviews, unsupported tax cases or an existing output path.

`generate` writes `return-review.html`, `return-data.json`, `report.html`,
`reviewed-config.json` and `computation.json`. These contain the saved facts,
reviewed computation and estimated balance after tax already paid. **The terminal
review workflow is implemented; a completed CT600/statutory accounts/iXBRL
generator is not yet implemented.** `return-data.json` explicitly records
`filing_ready: false` and the outstanding steps. Do not upload it as a return.

The commands below remain available for separately downloading and preparing
reports without an interactive review.

Login prints a URL to open on the **same computer** running the command; its
callback listener is bound to IPv4 loopback only. Login times out after ten
minutes. Tokens are stored with owner-only permissions under your OS user
configuration directory, in `companytax/token.json`. `--state DIR` overrides it.
A lock prevents two commands rotating the token concurrently. After an abrupt
termination, remove the lock only after checking no other command is running.
Unused Xero refresh tokens expire; run `login` again when instructed.

## Prepare Micro XYZ Ltd's first accounts period

The generated config contains company number 16607360 and accounts dates
25 July 2025–31 July 2026. Set `tenant_id` using `tenants` and enter the actual
`trading_start`. Do not assume incorporation was the trading start.

```sh
/tmp/companytax prepare --config /tmp/micro-companytax.json --out /tmp/micro-tax-first-pass
```

The tool verifies the selected UK/GBP organisation's name and, when Xero provides
it, registration number. An empty registration number in Xero must be checked
against your config manually. It downloads:

- Organisation details and chart of accounts.
- Accrual trial balance and balance sheet at the accounts end date.
- Accrual profit and loss for the full accounts period.
- Separate profit and loss reports for Corporation Tax periods of at most 12 months.

If trading started on 25 July 2025, the suggested periods are 25 July 2025–24 July
2026 and 25–31 July 2026. Confirm these against your HMRC record. Trial balance
year-to-date columns use Xero's financial year; the tool preserves its column
headings rather than treating them as the requested full accounts period.

The output directory contains original report JSON, a printable `report.html`,
`computation.json` and `period-reviews-template.json`. An existing output
directory is never overwritten. Failed downloads do not publish a partial pack.
This is a reports integration, not a full transaction/general-ledger export.

## Review and calculate

Copy the entries in `period-reviews-template.json` into the config's
`period_reviews` array. Check the exact profit-row label in each downloaded P&L;
it must match once. For each period, record signed tax adjustments in GBP, with
reasons, and mark `confirmed` true only after review. For example:

```json
{
  "from": "2025-07-25",
  "to": "2026-07-24",
  "confirmed": true,
  "profit_row_label": "Net Profit",
  "adjustments": [
    {"reason": "Add back depreciation", "amount_gbp": "500.00"},
    {"reason": "Deduct reviewed capital allowances", "amount_gbp": "-400.00"}
  ]
}
```

Set `associated_companies` to the number **excluding this company**; zero must
be entered explicitly. Where the count changes or needs financial-year-specific
treatment, use specialist filing software rather than this calculation.

Only set `ordinary_trading_only_confirmed` true when all of these apply:

- UK-resident ordinary trading company eligible for small-profits/marginal relief;
  not a close investment-holding company, ring-fence business or special regime.
- All taxable profits are ordinary trading profits. No interest/non-trading loan
  relationships, chargeable gains, property income or exempt distributions.
- No losses/claims, group relief, qualifying donations, R&D credits, overseas
  relief or director-loan tax. Those require additional computations.
- Booked Corporation Tax, depreciation and disallowable expenses have been
  reviewed and added back as needed; capital allowances are explicitly reviewed.
- Profit attribution to each short/long period has been reviewed. Separate Xero
  P&Ls are evidence, not a determination of the legally correct apportionment.

Rerun with a new output directory. For supported positive profits it calculates
19%, 25%, or marginal relief, using rational decimal arithmetic, associated-company
threshold division and day-based short-period limits. Rate coverage is restricted
to **1 April 2025–31 March 2027**. Negative adjusted profits remain blocked for
loss-relief review. Missing confirmations never silently become zero tax.

## What the output is

This is a **draft preparation working paper**, not complete statutory accounts,
a completed CT600, or HMRC-uploadable iXBRL. It supplies source accounts and the
supported trading-profit/tax computation for entering into your chosen filing
software. That software still needs the other CT600 fields, declarations,
financial-year allocation/rounding and statutory accounts/disclosures. It cannot
infer these from Xero reports. Print `report.html` from your browser if you want
a PDF for review. No AI is used to infer tax treatment.

## Validation

```sh
go test ./cmd/companytax
```

Tests use a simulated Xero API and cover refresh-token rotation, tenant headers,
report parameters, output protection, review blockers and tax-rate boundaries.
Live Xero access requires your app credentials and authorisation.

References:

- [Xero OAuth](https://developer.xero.com/documentation/guides/oauth2/auth-flow/)
- [Xero scopes](https://developer.xero.com/documentation/guides/oauth2/scopes/)
- [Xero reports](https://developer.xero.com/documentation/api/accounting/reports)
- [HMRC Corporation Tax rates](https://www.gov.uk/government/publications/rates-and-allowances-corporation-tax/rates-and-allowances-corporation-tax)
- [HMRC first accounts and returns](https://www.gov.uk/first-company-accounts-and-return)
