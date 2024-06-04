import { left, right, type Either } from '@/common/functional/brambl_fp.js';
import base58Check from 'bs58check';
import { LockAddress, LockId } from 'topl_common';
import { EncodingError, InvalidChecksum } from '../utils/encoding.js';

export class AddressCodecs {
  static uint8ArrayToNumber(uint8Array: Uint8Array): number {
    const bigIntValue = BigInt(
      '0x' +
        Array.from(uint8Array)
          .map((byte) => byte.toString(16).padStart(2, '0'))
          .join(''),
    );

    return Number(bigIntValue);
  }

  static decode(address: string): Either<EncodingError, LockAddress> {
    try {
      const decoded = base58Check.decode(address);
      const network = decoded.slice(0, 4);
      const ledgerAndId = decoded.slice(4);
      const ledger = ledgerAndId.slice(0, 4);
      const id = ledgerAndId.slice(4);

      const lockAddress = new LockAddress({
        network: AddressCodecs.uint8ArrayToNumber(network),
        ledger: AddressCodecs.uint8ArrayToNumber(ledger),
        id: new LockId({ value: id }),
      });
      return right(lockAddress);
    } catch (err) {
      return left(new InvalidChecksum());
    }
  }

  static encode(lockAddress: LockAddress): string {
    const networkBytes = new Uint8Array(4);
    const ledgerBytes = new Uint8Array(4);

    const view1 = new DataView(networkBytes.buffer);
    const view2 = new DataView(ledgerBytes.buffer);

    view1.setInt32(0, lockAddress.network, true);
    view2.setInt32(0, lockAddress.ledger, true);

    const idBytes = lockAddress.id.value;

    const bytes = new Uint8Array([...networkBytes, ...ledgerBytes, ...Array.from(idBytes)]);

    return base58Check.encode(bytes);
  }
}
