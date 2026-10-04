// Data-only RN contract. Native constructors and handles are intentionally absent.


export enum MobileNwcMethod {
    /**
     * Return wallet information.
     */
    GetInfo,
    /**
     * Return spendable balance.
     */
    GetBalance,
    /**
     * Create an invoice.
     */
    MakeInvoice,
    /**
     * Pay an invoice.
     */
    PayInvoice,
    /**
     * Look up one invoice or payment.
     */
    LookupInvoice,
    /**
     * List wallet transactions.
     */
    ListTransactions
}

export enum MobileBudgetInterval {
    /**
     * The budget never renews automatically.
     */
    Never,
    /**
     * Renew every hour.
     */
    Hourly,
    /**
     * Renew every day.
     */
    Daily,
    /**
     * Renew every seven days.
     */
    Weekly,
    /**
     * Renew every 30 days.
     */
    Monthly,
    /**
     * Renew every 365 days.
     */
    Yearly
}

export enum MobileNwcEncryption {
    /**
     * NIP-44 version 2 authenticated encryption.
     */
    Nip44V2,
    /**
     * Legacy NIP-04 compatibility mode.
     */
    LegacyNip04
}

export type MobileForegroundPayment = {
    purchaseJson?: string,
    /**
     * Original Nostr event identifier.
     */
    eventIdHex: string,
    /**
     * Authorizing connection identifier.
     */
    connectionId: string,
    /**
     * Exact requested BOLT11 invoice.
     */
    invoice: string,
    /**
     * Invoice payment hash.
     */
    paymentHashHex: string,
    /**
     * Exact principal in millisatoshis.
     */
    amountMsat: bigint,
    /**
     * Maximum fee allowed at execution in satoshis.
     */
    maximumFeeSat?: bigint,
    /**
     * capped or wallet_managed, bound during authorization.
     */
    feePolicy: string,
    /**
     * Actual recipient amount after successful reconciliation.
     */
    actualAmountMsat?: bigint,
    /**
     * Actual wallet-reported routing fee after reconciliation.
     */
    feeMsat?: bigint,
    /**
     * awaiting_approval, in_flight, succeeded, failed, or rejected.
     */
    state: string,
    /**
     * Opaque wallet bound by the first execution handoff.
     */
    walletId?: string
}

export type MobileFcmRegistrationReport = {
    /**
     * Successfully applied changes.
     */
    applied: bigint,
    /**
     * Provider failures retained for retry.
     */
    deferred: bigint,
    /**
     * Earliest remaining retry time in Unix seconds.
     */
    nextAttemptAt?: bigint
}

export type MobileApnsRegistrationReport = {
    /**
     * Successfully applied changes.
     */
    applied: bigint,
    /**
     * Provider failures retained for retry.
     */
    deferred: bigint,
    /**
     * Earliest remaining retry time in Unix seconds.
     */
    nextAttemptAt?: bigint
}

export type MobileBrowserPairingChallenge = {
    challengeId: string,
    connectionId: string,
    nonce: string,
    audience: string,
    expiresAtSeconds: bigint,
    clientPublicKeyHex: string,
    walletServicePublicKeyHex: string
}

export type MobileConnectionOptions = {
    /**
     * Approved methods; never silently grant all methods.
     */
    methods: Array<MobileNwcMethod>,
    /**
     * Principal plus fee spending limit per interval.
     */
    budgetLimitSat: bigint,
    /**
     * Spending-limit renewal interval.
     */
    budgetInterval: MobileBudgetInterval,
    /**
     * Negotiated encryption, normally NIP-44 v2.
     */
    encryption: MobileNwcEncryption,
    /**
     * Optional Unix expiry in seconds.
     */
    expiresAt?: bigint,
    /**
     * Username explicitly disclosed to this NWA client; omitted for old connections.
     */
    payerUsername?: string,
    /**
     * Selected spending wallet name, separate from payer identity.
     */
    walletName?: string,
    /**
     * Postal address snapshot explicitly disclosed during connection approval.
     */
    payerAddressJson?: string
}

export type MobileConnectionPresentation = {
    paymentMode: string,
    budgetBasis: string,
    /**
     * Explicit foreground extra-cost policy; budget is principal reservation for wallet_managed.
     */
    feePolicy: string,
    /**
     * Stable wallet-local identifier.
     */
    connectionId: string,
    /**
     * Authorized client public key.
     */
    clientPublicKeyHex: string,
    /**
     * Wallet-service public key.
     */
    walletServicePublicKeyHex: string,
    /**
     * Canonical secure relay allowlist.
     */
    relayUrls: Array<string>,
    /**
     * Exact implemented method allowlist.
     */
    methods: Array<MobileNwcMethod>,
    /**
     * Budget limit for one policy interval.
     */
    budgetLimitSat: bigint,
    /**
     * Budget renewal interval.
     */
    budgetInterval: MobileBudgetInterval,
    /**
     * Original creation timestamp.
     */
    createdAtSeconds: bigint,
    /**
     * Optional authorization expiration timestamp.
     */
    expiresAtSeconds?: bigint,
    /**
     * Latest successfully completed wake timestamp.
     */
    lastUsedAtSeconds?: bigint
}

export type MobileConnectionState = {
    /**
     * Stable wallet-local connection identifier.
     */
    connectionId: string,
    /**
     * Monotonic revision used for compare-and-revoke operations.
     */
    revision: bigint,
    /**
     * Whether this exact revision may authorize new requests.
     */
    active: boolean
}

export type MobileNwaRequestPresentation = {
    paymentMode: string,
    budgetBasis: string,
    /**
     * Explicit requested extra-cost policy: capped or wallet_managed.
     */
    feePolicy: string,
    /**
     * Untrusted bounded application metadata from the exact retained request.
     */
    metadataJson?: string,
    /**
     * Random identity binding approval to the retained request.
     */
    requestIdHex: string,
    /**
     * Requesting client's public key.
     */
    clientPublicKeyHex: string,
    /**
     * Sanitized, unverified requester name.
     */
    displayName: string,
    /**
     * Validated HTTPS icon URL, when supplied.
     */
    iconUrl?: string,
    /**
     * Syntactically validated but unverified callback host, when supplied.
     */
    requestingAppDescription?: string,
    /**
     * Syntactically validated but unverified callback target shown to the user.
     */
    callbackTargetDescription: string,
    /**
     * Exact secure relay list requested by the client.
     */
    relayUrls: Array<string>,
    /**
     * Requested spending limit in satoshis.
     */
    budgetLimitSat: bigint,
    /**
     * Requested budget renewal interval.
     */
    budgetInterval: MobileBudgetInterval,
    /**
     * Requested NWC methods in canonical order.
     */
    methods: Array<MobileNwcMethod>,
    /**
     * Optional connection expiration timestamp.
     */
    expiresAt?: bigint,
    /**
     * Exclusive approval deadline, separate from the connection expiration.
     */
    requestExpiresAtSeconds?: bigint
}

export type MobileNwaApprovalResult = {
    /**
     * Durable connection lifecycle state.
     */
    connection: MobileConnectionState,
    /**
     * Validated but unverified public callback URL, when supplied.
     * Native hosts must verify any claimed app-link association independently.
     */
    callbackUrl?: string
}

export const engineErrorTags = ['InvalidArgument', 'DatabaseUnavailable', 'UnsupportedSchema', 'CorruptData',
  'AlreadyExists', 'NotFound', 'StaleRevision', 'AlreadyRevoked', 'InvalidNwaRequest',
  'NwaAlreadyPending', 'NoPendingNwa', 'NwaAuthorityEscalation'] as const;
export class MobileEngineError extends Error {
  constructor(readonly tag: typeof engineErrorTags[number]) {
    super('Native NWC request failed');
    this.name = 'MobileEngineError';
  }
  static instanceOf(value: unknown): value is MobileEngineError { return value instanceof MobileEngineError; }
}
