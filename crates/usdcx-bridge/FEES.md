# Set withdrawal fee limits

These settings limit what the withdrawal attester will accept. They do not set a fee paid to the
service operator. Fees are deducted from the withdrawal amount.

Use the API for the deployment's environment. Check every destination and the range of withdrawal
amounts the deployment needs to support. Do not copy testnet estimates into mainnet configuration.

## 1. Estimate the additional CCTP fee

Some withdrawals go through Arc and then CCTP. For those routes, query Circle's
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
- `forwardFee.high` is a gas and forwarding estimate in USDC base units. Use this higher estimate
  when sizing a shared cap across destinations.

Calculate, rounding each result up to a whole base unit:

```text
protocol fee = CCTP transfer amount in base units × minimumFee / 10000
CCTP estimate = protocol fee + forwardFee.high
CCTP cap = CCTP estimate × 1.20
```

Circle recommends a [10–20% buffer](https://developers.circle.com/cctp/concepts/fees). The formula
above uses 20%. For initial sizing, use the largest planned burn amount as a conservative upper
bound for the CCTP transfer amount. Set `--cctp-forwarding-max-fee` to the largest buffered result
across the CCTP destinations you support. It must be greater than zero.

For example, an estimate of `250000` base units (0.25 USDC) gives a cap of `300000` (0.30 USDC).
This is a calculation example, not a recommended deployment value. A larger cap can prevent small
withdrawals from passing verification, so also check the smallest supported withdrawal amount.

## 2. Get Circle's xReserve withdrawal fee

Call `POST /v1/prepare-withdrawal` on the same xReserve API used by `--circle-url`.
Create `prepare.json` from this template, replacing every placeholder. The request format is in
Circle's [xReserve API schema](https://developers.circle.com/openapi/xreserve.yaml).

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

Encode the sender with `EthEmbeddedAccountId::from_account_id(sender).to_bytes32()` from
`miden-standards`; do not simply pad the displayed Miden account ID. Both address fields use
`0x`-prefixed hex; use the recipient format required by the destination chain. Request amounts are
decimal USDC strings: for example, a `300000` CLI cap becomes `"0.300000"` here.

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

## 3. Set the total allowance

The attester checks this limit, with the proportional part rounded down to a base unit:

```text
allowed fee = --max-withdrawal-fee + (burn amount × --max-withdrawal-fee-bps / 10000)
```

For a CCTP route, Circle's returned `maxFee` plus the **full configured CCTP cap** must fit.
For a direct route, only Circle's returned `maxFee` counts. The CCTP cap is still a required
positive setting, but is not added to the direct route's check. For CCTP, the burn amount minus
Circle's fee must also be strictly greater than the CCTP cap, leaving a positive payout.

Choose a whole-number basis-point allowance for the amount-dependent part of the fees, then a
fixed allowance large enough to cover the remaining costs and headroom across the checked routes
and amounts. For each quote, subtract the proportional allowance from the required total; the
fixed allowance must cover the largest remainder, plus the chosen headroom. Check the smallest
and largest withdrawals against the formula. `1000000` base units is 1 USDC; `1` basis point is
0.01%. These are acceptance limits, not values to overwrite in a
prepared withdrawal.

There is no universal set of three safe numbers. Limits that are too low can stop withdrawals;
excessively high limits allow larger charges and can also block small CCTP withdrawals. Review
current fees before launch and regularly afterward. The service does not refresh caps automatically.
To change them, stop and recreate the container with updated flags and the same durable volume.
Do not delete state or automatically raise limits to clear an error.
