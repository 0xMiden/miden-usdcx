# Set withdrawal fee limits

These settings limit what the withdrawal attester will accept. They do not set a fee paid to the
service operator. Fees are deducted from the withdrawal amount.

Use the API for the deployment's environment. Check every destination and the range of withdrawal
amounts the deployment needs to support. Do not copy testnet estimates into mainnet configuration.

## 1. Check which withdrawal route applies

The bridge always requests `useCircleForwarding: true`, asking Circle to deliver the withdrawal.
That does **not** mean every withdrawal uses CCTP.

| Route | Fee to check |
| --- | --- |
| Direct payout on Arc, Base, Arbitrum or Ethereum | Circle's xReserve prepare quote. No additional CCTP cap is added. |
| Payout through Arc with an additional CCTP transfer | The xReserve prepare quote plus the configured CCTP cap. |

Circle's [withdrawal route guide](https://developers.circle.com/xreserve/concepts/technical-guide)
explains direct payouts through Circle Gateway, its cross-chain transfer product. Arc, Base,
Arbitrum and Ethereum are [supported destinations](https://developers.circle.com/gateway/references/supported-blockchains).
Confirm the route with the target environment's prepare response, not the destination name alone.
These instructions cover withdrawals from Miden, not fees for deposits into Miden.

## 2. Get Circle's xReserve withdrawal fee

Call `POST /v1/prepare-withdrawal` on the same xReserve API used by `--circle-url`.
Miden's domain `10007` must be enabled there. An unsuccessful request is not a zero-fee quote.
Create `prepare.json` from this template, replacing every placeholder. The request format is in
Circle's [xReserve API schema](https://developers.circle.com/openapi/xreserve.yaml).
For a CCTP route, estimate the cap in section 3 first. The service sends `forwardingOptions` for
direct routes too, so keep those fields in the request.

```json
{
  "batches": [{
    "token": "USDC",
    "remoteDomain": 10007,
    "remoteDepositor": "<MIDEN_SENDER_AS_32_BYTE_HEX>",
    "finalDestinationDomain": <CIRCLE_DESTINATION_DOMAIN>,
    "finalDestinationRecipient": "<DESTINATION_RECIPIENT_AS_32_BYTE_HEX>",
    "valueIncludingFees": "<BURN_AMOUNT_IN_USDC>",
    "useCircleForwarding": true,
    "forwardingOptions": {
      "maxFee": "<CCTP_CAP_IN_USDC>",
      "usesFastFinality": true
    }
  }]
}
```

Obtain a quote-ready Miden sender value, destination domain ID and encoded recipient from the
network deployment owner. You can then fill the template without writing Rust or converting
account IDs yourself.

For whoever prepares these values: the sender uses
`EthEmbeddedAccountId::from_account_id(sender).to_bytes32()` from `miden-standards`; do not simply
pad the displayed Miden account ID. Both address fields use `0x`-prefixed hex, and the recipient
must use the destination chain's format. Request amounts are decimal USDC strings: for example,
a `300000` CLI cap becomes `"0.300000"` here.

```sh
XRESERVE_API='<CIRCLE_XRESERVE_HTTPS_URL>'
curl --fail --silent --show-error --max-time 30 \
  -H 'Content-Type: application/json' --data-binary @prepare.json \
  "$XRESERVE_API/v1/prepare-withdrawal"
```

Read `batches[0].burnIntents[0].maxFee` from a successful response. Unlike the request amounts,
this is an integer string in USDC base units. It is Circle's fee for the xReserve part, excluding
the additional CCTP cap. This attester supports one returned burn intent; do not sum multiple
intents and assume that route is supported. Preparing is not submitting: do not sign the response
or call `/v1/withdraw` to check fees.

In the returned intent's `spec`, a direct route has the requested destination domain and recipient,
with `hookData.forwardingContractAddress` all zeroes and `hookData.forwardingCalldata` equal to `0x`.
The supported CCTP route instead pays xReserve on Arc and includes a TokenMessengerV2 call in the
hook. The attester verifies that call against the burn and the configured Arc contracts. Do not
treat an unexpected hook or an unsuccessful quote as a supported route.

## 3. Estimate the additional CCTP fee, if needed

Skip this lookup for direct routes. For an Arc-to-CCTP route, query Circle's
[CCTP fee API](https://developers.circle.com/api-reference/cctp/all/get-burn-usdc-fees):

```sh
CCTP_API='<CCTP_API_BASE_URL>'
DESTINATION_DOMAIN='<CIRCLE_DESTINATION_DOMAIN>'
curl --fail --silent --show-error --max-time 30 \
  "$CCTP_API/v2/burn/USDC/fees/26/$DESTINATION_DOMAIN?forward=true"
```

Use `https://iris-api.circle.com` for mainnet or `https://iris-api-sandbox.circle.com` for testnet.
The source is Arc's Circle domain `26`, not Miden's domain `10007`. The destination must be a
Circle domain ID, not an EVM chain ID. No signing key is needed for this GET request.

Use the entry with `finalityThreshold: 1000`, matching the attester's fast-finality request:

- `minimumFee` is a rate in basis points, not a USDC amount.
- `forwardFee.high` is a gas and forwarding estimate in USDC base units.

Calculate, rounding each result up to a whole base unit:

```text
protocol fee = CCTP transfer amount in base units × minimumFee / 10000
CCTP estimate = protocol fee + forwardFee.high
CCTP cap = CCTP estimate × 1.20
```

Circle suggests a [10–20% buffer](https://developers.circle.com/cctp/concepts/fees); this uses 20%.
For initial sizing, use the largest planned burn as an upper bound for the CCTP transfer amount.
Set `--cctp-forwarding-max-fee` to the largest buffered result across the supported CCTP routes.
For example, `250000` base units (0.25 USDC) gives a cap of `300000` (0.30 USDC). This is a
calculation example, not a deployment default. Use that cap in the prepare request too.

## 4. Set the total allowance

The attester checks this limit, with the proportional part rounded down to a base unit:

```text
allowed fee = --max-withdrawal-fee + (burn amount × --max-withdrawal-fee-bps / 10000)
```

For a CCTP route, Circle's returned `maxFee` plus the **full configured CCTP cap** must fit.
For a direct route, only Circle's returned `maxFee` counts. The CCTP cap is still a required
positive setting, but is not added to the direct route's check. For CCTP, the burn amount minus
Circle's fee must also be strictly greater than the CCTP cap, leaving a positive payout.

For initial setup, allow 20% headroom above each xReserve quote, rounding up, then add the CCTP
cap only where applicable. Choose whole basis points for the amount-dependent part; set the fixed
allowance to cover the largest remaining cost across the checked quotes. A fixed-only allowance
(`--max-withdrawal-fee-bps 0`) is also valid if it covers the whole planned amount range. Check
both the smallest and largest withdrawals. `1000000` base units is 1 USDC; `1` basis point is 0.01%.
The 20% margin is a setup choice, not a guarantee against fee changes. These settings are acceptance
limits: do not overwrite values in the prepared withdrawal.

There is no universal set of three safe numbers. Limits that are too low can stop withdrawals;
excessively high limits allow larger charges and can also block small CCTP withdrawals. Review
current fees before launch and regularly afterward. The service does not refresh caps automatically.
To change them, stop and recreate the container with updated flags and the same durable volume.
Do not delete state or automatically raise limits to clear an error.
