import { MobileBudgetInterval, MobileNwcEncryption, MobileNwcMethod, MobileEngineError, engineErrorTags } from './types';
const maxU64 = (1n << 64n) - 1n;
const enums: Record<string, Record<string | number, string | number>> = {
  budgetInterval: MobileBudgetInterval, encryption: MobileNwcEncryption, methods: MobileNwcMethod,
};

export function encodeRequest(command: Record<string, unknown>): string {
  function encode(value: unknown, key = ''): unknown {
    if (typeof value === 'bigint') {
      if (value < 0n || value > maxU64) throw new RangeError('Unsigned integer out of range');
      return value.toString();
    }
    if (Array.isArray(value)) return value.map(item => encode(item, key));
    if (value !== null && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, encode(v, k)]));
    }
    if (value !== undefined && enums[key]) {
      if (typeof value !== 'number' || !Number.isInteger(value) || typeof enums[key][value] !== 'string') {
        throw new TypeError('Invalid NWC enum');
      }
      return enums[key][value];
    }
    return value;
  }
  const result = JSON.stringify(encode(command));
  if (result.length > 131072) throw new RangeError('NWC request is too large');
  return result;
}

export function decodeResponse(response: string): unknown {
  if (response.length > 2097152) throw new RangeError('NWC response is too large');
  function decode(value: unknown, key = ''): unknown {
    if (value === null) return undefined;
    if (Array.isArray(value)) return value.map(item => decode(item, key));
    if (typeof value === 'object') {
      const record = value as Record<string, unknown>;
      if ('$nwcU64' in record) {
        const digits = record.$nwcU64;
        if (Object.keys(record).length !== 1 || typeof digits !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(digits)) {
          throw new TypeError('Invalid native integer');
        }
        const number = BigInt(digits);
        if (number > maxU64) throw new RangeError('Native integer out of range');
        return number;
      }
      return Object.fromEntries(Object.entries(record).map(([k, v]) => [k, decode(v, k)]));
    }
    if (enums[key]) {
      if (typeof value !== 'string' || typeof enums[key][value] !== 'number') throw new TypeError('Invalid native enum');
      return enums[key][value];
    }
    return value;
  }
  const parsed: unknown = JSON.parse(response);
  if (parsed !== null && typeof parsed === 'object' && '$nwcError' in parsed) {
    const tag = engineErrorTags.find(tag => tag === parsed.$nwcError);
    if (!tag || Object.keys(parsed).length !== 1) throw new TypeError('Invalid native error');
    throw new MobileEngineError(tag);
  }
  return decode(parsed);
}
