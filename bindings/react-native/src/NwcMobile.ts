import type { MobileConnectionOptions, MobileConnectionPresentation, MobileNwaRequestPresentation,
  MobileNwaApprovalResult, MobileBrowserPairingChallenge, MobileFcmRegistrationReport,
  MobileApnsRegistrationReport, MobileForegroundPayment } from './types';
import { encodeRequest, decodeResponse } from './protocol';
declare const require: (id: './NativeNwcMobile') => typeof import('./NativeNwcMobile');

export interface NwcMobileConfig { walletId: string; }
/** Native-configured UI operations. The host must trust its JavaScript consent UI. */
export class NwcMobile {
  private constructor(private readonly walletId: string) {}
  static async open(config: NwcMobileConfig): Promise<NwcMobile> {
    const wallet = new NwcMobile(config.walletId);
    await wallet.servicePublicKey();
    return wallet;
  }
  private async request<T>(command: Record<string, unknown>): Promise<T> {
    const native = require('./NativeNwcMobile').default;
    return decodeResponse(await native.dispatch(this.walletId, encodeRequest(command))) as T;
  }
  async servicePublicKey(): Promise<string> {
    return this.request({ method: "servicePublicKey" });
  }
  async listConnections(): Promise<MobileConnectionPresentation[]> {
    return this.request({ method: "listConnections" });
  }
  async revokeConnection(connectionId: string): Promise<boolean> {
    return this.request({ method: "revokeConnection", connectionId });
  }
  async parseNwaRequest(uri: string): Promise<MobileNwaRequestPresentation> {
    return this.request({ method: "parseNwaRequest", uri });
  }
  async pendingNwaRequest(): Promise<MobileNwaRequestPresentation | undefined> {
    return this.request({ method: "pendingNwaRequest" });
  }
  async approveNwaRequest(requestId: string, options: MobileConnectionOptions): Promise<MobileNwaApprovalResult> {
    return this.request({ method: "approveNwaRequest", requestId, options });
  }
  async approveNwaReusablePayment(requestId: string, options: MobileConnectionOptions, walletId: string): Promise<MobileNwaApprovalResult> {
    return this.request({ method: "approveNwaReusablePayment", requestId, options, walletId });
  }
  async approveNwaWalletManagedPayment(requestId: string, options: MobileConnectionOptions, walletId: string, invoice: string, paymentHashHex: string, invoiceAmountMsat: bigint): Promise<MobileNwaApprovalResult> {
    return this.request({ method: "approveNwaWalletManagedPayment", requestId, options, walletId, invoice, paymentHashHex, invoiceAmountMsat });
  }
  async cancelNwaRequest(): Promise<void> {
    return this.request({ method: "cancelNwaRequest" });
  }
  async parseBrowserPairingChallenge(connectionId: string, signedEncryptedEventJson: string): Promise<MobileBrowserPairingChallenge> {
    return this.request({ method: "parseBrowserPairingChallenge", connectionId, signedEncryptedEventJson });
  }
  async approveBrowserPairing(challengeId: string): Promise<boolean> {
    return this.request({ method: "approveBrowserPairing", challengeId });
  }
  async cancelBrowserPairing(challengeId: string): Promise<void> {
    return this.request({ method: "cancelBrowserPairing", challengeId });
  }
  async refreshWakeRegistrations(enabled: boolean): Promise<bigint> {
    return this.request({ method: "refreshWakeRegistrations", enabled });
  }
  async processFcmWakeRegistrations(serverUrl: string, pushToken: string, appId: string, installId: string): Promise<MobileFcmRegistrationReport> {
    return this.request({ method: "processFcmWakeRegistrations", serverUrl, pushToken, appId, installId });
  }
  async processApnsWakeRegistrations(serverUrl: string, pushToken: string, appId: string, installId: string, environment: string): Promise<MobileApnsRegistrationReport> {
    return this.request({ method: "processApnsWakeRegistrations", serverUrl, pushToken, appId, installId, environment });
  }
  async bindConnectionPayment(connectionId: string, walletId: string, paymentHashHex: string, amountMsat: bigint, maximumFeeSat: bigint): Promise<void> {
    return this.request({ method: "bindConnectionPayment", connectionId, walletId, paymentHashHex, amountMsat, maximumFeeSat });
  }
  async pollRequests(executionMilliseconds: bigint = 25_000n): Promise<number> {
    return this.request({ method: "pollRequests", executionMilliseconds });
  }
  async listPendingPayments(): Promise<MobileForegroundPayment[]> {
    return this.request({ method: "listPendingPayments" });
  }
  async beginPayment(eventIdHex: string, walletId: string): Promise<MobileForegroundPayment> {
    return this.request({ method: "beginPayment", eventIdHex, walletId });
  }
  async beginPaymentWithConsent(eventIdHex: string, walletId: string, customerDataJson: string): Promise<MobileForegroundPayment> {
    return this.request({ method: "beginPaymentWithConsent", eventIdHex, walletId, customerDataJson });
  }
  async completePayment(eventIdHex: string, preimageHex: string, amountMsat: bigint, feeMsat: bigint): Promise<void> {
    return this.request({ method: "completePayment", eventIdHex, preimageHex, amountMsat, feeMsat });
  }
  async rejectPayment(eventIdHex: string): Promise<void> {
    return this.request({ method: "rejectPayment", eventIdHex });
  }
  async failPayment(eventIdHex: string): Promise<void> {
    return this.request({ method: "failPayment", eventIdHex });
  }
  async resumePayment(eventIdHex: string, executionMilliseconds: bigint = 25_000n): Promise<void> {
    return this.request({ method: "resumePayment", eventIdHex, executionMilliseconds });
  }
}
