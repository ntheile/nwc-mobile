import type {
  MobileConnectionOptions,
  MobileWalletLike,
} from './generated/nwc_mobile_uniffi';

declare const require: (id: './native') => typeof import('./native');

export interface NwcMobileConfig {
  /** Opaque identifier resolved by the native host. Never a path or secret. */
  walletId: string;
}

/** Connection and approval UI facade. Background processing stays native. */
export class NwcMobile {
  private constructor(private readonly wallet: MobileWalletLike) {}

  static async open(config: NwcMobileConfig): Promise<NwcMobile> {
    // Load only when opening: importing types or rendering an unconnected
    // screen does not install JSI or open the wallet.
    // Literal require is bundled by Metro without a development-server split
    // request, while still deferring JSI initialization until the first open.
    const native = require('./native');
    return new NwcMobile(native.openRegisteredMobileWallet(config.walletId));
  }

  /** Wrap an existing native wallet, e.g. an application's Rust composition. */
  static fromNativeWallet(wallet: MobileWalletLike): NwcMobile {
    return new NwcMobile(wallet);
  }

  async servicePublicKey() { return this.wallet.servicePublicKey(); }

  async listConnections() {
    return this.wallet.listConnections();
  }

  /**
   * Create an explicitly approved connection. Rust generates client keys and
   * stores them using the native secure store; JS supplies only policy.
   */
  async createConnection(approval: MobileConnectionOptions) {
    return this.wallet.createConnection(approval);
  }

  /** Secret-bearing value: only request for an explicit QR/share interaction. */
  async exportConnectionUri(connectionId: string) {
    return this.wallet.exportConnectionUri(connectionId);
  }

  async revokeConnection(connectionId: string) {
    // Idempotent host revocation also handles already-revoked connections.
    return this.wallet.revokeConnection(connectionId);
  }

  /** Parse and retain a request for review. Does not approve or open a URL. */
  async parseNwaRequest(uri: string) {
    return this.wallet.parseNwaRequest(uri);
  }

  async pendingNwaRequest() {
    return this.wallet.pendingNwaRequest();
  }

  /** Bind explicit approval to the exact request displayed by the UI. */
  async approveNwaRequest(requestId: string, approval: MobileConnectionOptions) {
    return this.wallet.approveNwaRequest(requestId, approval);
  }

  async parseBrowserPairingChallenge(connectionId: string, signedEncryptedEventJson: string) { return this.wallet.parseBrowserPairingChallenge(connectionId, signedEncryptedEventJson); }
  async approveBrowserPairing(challengeId: string) { return this.wallet.approveBrowserPairing(challengeId); }
  async cancelBrowserPairing(challengeId: string) { return this.wallet.cancelBrowserPairing(challengeId); }
  async approveNwaReusablePayment(requestId: string, approval: MobileConnectionOptions, walletId: string) { return this.wallet.approveNwaReusablePayment(requestId, approval, walletId); }
  async beginPaymentWithConsent(eventId: string, walletId: string, customerDataJson: string) { return this.wallet.beginPaymentWithConsent(eventId, walletId, customerDataJson); }
  async approveNwaWalletManagedPayment(requestId: string, approval: MobileConnectionOptions, walletId: string, invoice: string, paymentHashHex: string, invoiceAmountMsat: bigint) { return this.wallet.approveNwaWalletManagedPayment(requestId, approval, walletId, invoice, paymentHashHex, invoiceAmountMsat); }

  async cancelNwaRequest() {
    return this.wallet.cancelNwaRequest();
  }

  /** Queue updates; native maintenance delivers them to the push provider. */
  async refreshWakeRegistrations(enabled: boolean) {
    return this.wallet.refreshWakeRegistrations(enabled);
  }
  async processFcmWakeRegistrations(serverUrl: string, pushToken: string, appId: string, installId: string) { return this.wallet.processFcmWakeRegistrations(serverUrl, pushToken, appId, installId); }
  async processApnsWakeRegistrations(serverUrl: string, pushToken: string, appId: string, installId: string, environment: 'sandbox' | 'production') { return this.wallet.processApnsWakeRegistrations(serverUrl, pushToken, appId, installId, environment); }
  async bindConnectionPayment(connectionId: string, walletId: string, paymentHashHex: string, amountMsat: bigint, maximumFeeSat: bigint) { return this.wallet.bindConnectionPayment(connectionId, walletId, paymentHashHex, amountMsat, maximumFeeSat); }
  async pollRequests(executionMilliseconds: bigint = 25_000n) { return this.wallet.pollRequests(executionMilliseconds); }
  async listPendingPayments() { return this.wallet.listPendingPayments(); }
  async beginPayment(eventIdHex: string, walletId: string) { return this.wallet.beginPayment(eventIdHex, walletId); }
  async completePayment(eventIdHex: string, preimageHex: string, amountMsat: bigint, feeMsat: bigint) { return this.wallet.completePayment(eventIdHex, preimageHex, amountMsat, feeMsat); }
  async rejectPayment(eventIdHex: string) { return this.wallet.rejectPayment(eventIdHex); }
  async failPayment(eventIdHex: string) { return this.wallet.failPayment(eventIdHex); }
  async resumePayment(eventIdHex: string, executionMilliseconds: bigint = 25_000n) { return this.wallet.resumePayment(eventIdHex, executionMilliseconds); }

}
