import React, { useState } from 'react';
import { Button, ScrollView, Text, TextInput, View } from 'react-native';
import { NwcMobile, MobileBudgetInterval, MobileNwcEncryption, MobileNwcMethod, MobileEngineError } from '../src';
import type { MobileConnectionPresentation, MobileNwaRequestPresentation } from '../src';

/** Mount after native bootstrap registers the demo/host wallet as "primary". */
export default function App() {
  const [wallet, setWallet] = useState<NwcMobile>();
  const [connections, setConnections] = useState<MobileConnectionPresentation[]>([]);
  const [uri, setUri] = useState('');
  const [request, setRequest] = useState<MobileNwaRequestPresentation>();
  const [message, setMessage] = useState('Native wallet bootstrap is required.');
  const [busy, setBusy] = useState(false);

  async function action(work: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    try { await work(); }
    catch (error) {
      // Exception type only; never display raw native messages or values.
      const category = error && typeof error === 'object' && MobileEngineError.instanceOf(error)
        ? error.tag : error instanceof Error ? error.name : 'native error';
      setMessage(`Operation failed (${category}). Check native configuration.`);
    }
    finally { setBusy(false); }
  }

  return <ScrollView contentContainerStyle={{ padding: 24, gap: 16 }}>
    <Text>NWC native integration example</Text>
    <Text>{message}</Text>
    <Button disabled={busy} title="Open native wallet" onPress={() => action(async () => {
      const opened = await NwcMobile.open({ walletId: 'primary' });
      setWallet(opened);
      setConnections(await opened.listConnections());
      setMessage('Connected to native Rust engine.');
    })} />
    <Button disabled={busy || !wallet} title="Create read-only connection" onPress={() => action(async () => {
      if (!wallet) return;
      await wallet.createConnection({ methods: [MobileNwcMethod.GetInfo, MobileNwcMethod.GetBalance],
        budgetLimitSat: 0n, budgetInterval: MobileBudgetInterval.Never,
        encryption: MobileNwcEncryption.Nip44V2, expiresAt: undefined });
      setConnections(await wallet.listConnections());
      setMessage('Created read-only connection. No payment permission granted.');
    })} />
    {connections.map(connection => <View key={connection.connectionId}>
      <Text>{connection.methods.map(method => MobileNwcMethod[method]).join(', ')} — budget {connection.budgetLimitSat.toString()} sats</Text>
      <Button disabled={busy} title="Revoke" onPress={() => action(async () => {
        if (!wallet) return;
        const deleted = await wallet.revokeConnection(connection.connectionId);
        setConnections(await wallet.listConnections());
        setMessage(deleted ? 'Revoked.' : 'Revoked; native secret cleanup needs retry.');
      })} />
    </View>)}
    <TextInput accessibilityLabel="NWA request" placeholder="NWA link" value={uri} onChangeText={setUri}
      autoCapitalize="none" autoCorrect={false} />
    <Button disabled={busy || !wallet} title="Review NWA request" onPress={() => action(async () => {
      if (!wallet) return;
      setRequest(await wallet.parseNwaRequest(uri));
      setUri('');
    })} />
    {request && <View>
      <Text>Unverified app: {request.displayName}</Text>
      <Text>Requested methods: {request.methods.map(method => MobileNwcMethod[method]).join(', ')}</Text>
      <Text>Requested budget: {request.budgetLimitSat.toString()} sats</Text>
      <Text>Callback: {request.callbackTargetDescription}</Text>
      <Text>This demo only approves read-only access, never spending permission.</Text>
      <Button disabled={busy || !wallet} title="Approve read-only access" onPress={() => action(async () => {
        if (!wallet) return;
        await wallet.approveNwaRequest(request.requestIdHex, {
          methods: request.methods.filter(method => method === MobileNwcMethod.GetInfo || method === MobileNwcMethod.GetBalance),
          budgetLimitSat: 0n, budgetInterval: request.budgetInterval,
          encryption: MobileNwcEncryption.Nip44V2, expiresAt: request.expiresAt,
        });
        // A real host delivers any callback through its verified native flow.
        // Never pass it blindly to Linking.openURL.
        setConnections(await wallet.listConnections());
        setMessage('Approved. Native callback delivery remains the host’s responsibility.');
        setRequest(undefined);
      })} />
      <Button disabled={busy} title="Cancel" onPress={() => action(async () => {
        await wallet?.cancelNwaRequest(); setRequest(undefined);
      })} />
    </View>}
  </ScrollView>;
}
