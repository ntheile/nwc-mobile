import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';

/** Strings only: no Rust pointers, allocators, callbacks or native constructors. */
export interface Spec extends TurboModule {
  dispatch(walletId: string, request: string): Promise<string>;
}
export default TurboModuleRegistry.getEnforcing<Spec>('NwcMobile');
