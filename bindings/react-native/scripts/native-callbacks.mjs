// UniFFI callback vtables are process-global. Initializing the JS bindings must
// not overwrite the Swift/Kotlin implementations used by the native wallet.
// Keep checksum/version validation intact; only remove automatic JS callbacks.
export function retainNativeCallbacks(source) {
  const expected = [
    'MobileClientSecretStore', 'MobileRelayTransport', 'MobileSecretProvider',
    'MobileWakeRegistrationTransport', 'MobileWalletBackend', 'MobileWalletFactory',
  ].sort();
  const pattern = /^\s*uniffiCallbackInterface(\w+)\.register\(\);$/gm;
  const actual = [...source.matchAll(pattern)].map(match => match[1]).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error('UniFFI callback inventory changed; review native-only initialization before regenerating');
  }
  return source.replace(pattern, (_line, name) => `\n    // ${name} callback table is owned by native bootstrap, not JS.`);
}
