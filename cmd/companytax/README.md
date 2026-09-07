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
