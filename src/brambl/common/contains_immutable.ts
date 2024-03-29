import {
  ImmutableBytes,
  Lock,
  Lock_Predicate,
  Lock_Commitment,
  Lock_Image,
  AccumulatorRootId,
  Event_GroupPolicy,
  SeriesId,
  TransactionOutputAddress,
  TransactionId,
  Event_SeriesPolicy,
} from './types.js';
import { Evidence } from './types.js';
import { Digest } from '../../quivr4s/common/types.js';
import { Identifier } from '../common/tags.js';

export class ContainsImmutable {
  public immutableBytes: ImmutableBytes;

  constructor(immutableBytes: ImmutableBytes) {
    this.immutableBytes = immutableBytes;
  }

  //operations
  static addImmutableBytes(iBOne: ImmutableBytes, iBTwo: ImmutableBytes): ImmutableBytes {
    const mergedArray = new Uint8Array(iBOne.value.length + iBTwo.value.length);
    mergedArray.set(iBOne.value);
    mergedArray.set(iBTwo.value, iBOne.value.length);
    return new ImmutableBytes({ value: mergedArray });
  }

  static addContainsImmutable(cIOne: ContainsImmutable, cITwo: ContainsImmutable): ContainsImmutable {
    return new ContainsImmutable(ContainsImmutable.addImmutableBytes(cIOne.immutableBytes, cITwo.immutableBytes));
  }

  //factories
  static evidence(evidence: Evidence): ContainsImmutable {
    return ContainsImmutable.digest(evidence.digest);
  }

  static digest(digest: Digest): ContainsImmutable {
    const digestValue = digest.value;
    const bytes = new ImmutableBytes({ value: digestValue });
    return new ContainsImmutable(bytes);
  }

  static int(i: number): ContainsImmutable {
    const byteArray = Uint8Array.from([i]);
    const immutableBytes = new ImmutableBytes({ value: byteArray });
    return new ContainsImmutable(immutableBytes);
  }

  static string(str: string): ContainsImmutable {
    const encoder = new TextEncoder();
    const uint8Array = encoder.encode(str);
    const immutableBytes = new ImmutableBytes({ value: uint8Array });
    return new ContainsImmutable(immutableBytes);
  }

  static empty(): ContainsImmutable {
    return new ContainsImmutable(new ImmutableBytes());
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static list(list: any[]): ContainsImmutable {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return list.reduce((acc: ContainsImmutable, entry: any, index: number) => {
      const intResult = ContainsImmutable.int(index);
      const applyResult = ContainsImmutable.apply(entry);

      const partiallyCombinedContainsImmutable = ContainsImmutable.addContainsImmutable(acc, intResult);
      return ContainsImmutable.addContainsImmutable(partiallyCombinedContainsImmutable, applyResult);
    }, ContainsImmutable.empty());
  }

  static accumulatorRoot32Identifier(id: AccumulatorRootId): ContainsImmutable {
    return ContainsImmutable.addContainsImmutable(
      ContainsImmutable.string(Identifier.accumulatorRoot32),
      new ContainsImmutable(new ImmutableBytes({ value: id.value })),
    );
  }

  static predicateLock(predicate: Lock_Predicate): ContainsImmutable {
    return ContainsImmutable.addContainsImmutable(
      ContainsImmutable.int(predicate.threshold),
      ContainsImmutable.list(predicate.challenges),
    );
  }

  static imageLock(image: Lock_Image): ContainsImmutable {
    return ContainsImmutable.addContainsImmutable(
      ContainsImmutable.int(image.threshold),
      ContainsImmutable.list(image.leaves),
    );
  }

  static commitmentLock(commitment: Lock_Commitment): ContainsImmutable {
    const thresholdContainsImmutable = ContainsImmutable.int(commitment.threshold);
    const lengthContainsImmutable = ContainsImmutable.int(commitment.root.value.length);
    const rootContainsImmutable = ContainsImmutable.accumulatorRoot32Identifier(commitment.root);

    const partiallyMergedContainsImmutable = ContainsImmutable.addContainsImmutable(
      thresholdContainsImmutable,
      lengthContainsImmutable,
    );
    return ContainsImmutable.addContainsImmutable(partiallyMergedContainsImmutable, rootContainsImmutable);
  }

  static lock(lock: Lock): ContainsImmutable {
    if (lock.has_predicate) {
      return ContainsImmutable.predicateLock(lock.predicate);
    } else if (lock.has_image) {
      return ContainsImmutable.imageLock(lock.image);
    } else if (lock.has_commitment) {
      return ContainsImmutable.commitmentLock(lock.commitment);
    } else {
      throw Error(`Invalid lock type ${typeof lock}`);
    }
  }

  static seriesIdValue(sid: SeriesId) {
    return ContainsImmutable.addContainsImmutable(
      ContainsImmutable.string(Identifier.series32),
      new ContainsImmutable(new ImmutableBytes({ value: sid.value })),
    );
  }

  static transactionIdentifier(id: TransactionId) {
    return ContainsImmutable.addContainsImmutable(
      ContainsImmutable.string(Identifier.ioTransaction32),
      new ContainsImmutable(new ImmutableBytes({ value: id.value })),
    );
  }

  static transactionOutputAddress(v: TransactionOutputAddress) {
    const networkAndLedgerContainsImmutable = ContainsImmutable.addContainsImmutable(
      ContainsImmutable.int(v.network),
      ContainsImmutable.int(v.ledger),
    );
    const combinedIntContainsImmutable = ContainsImmutable.addContainsImmutable(
      networkAndLedgerContainsImmutable,
      ContainsImmutable.int(v.index),
    );
    return ContainsImmutable.addContainsImmutable(
      combinedIntContainsImmutable,
      ContainsImmutable.transactionIdentifier(v.id),
    );
  }

  static groupPolicyEvent(groupPolicy: Event_GroupPolicy) {
    const partiallyCombinedContainsImmutable = ContainsImmutable.addContainsImmutable(
      ContainsImmutable.string(groupPolicy.label),
      ContainsImmutable.seriesIdValue(groupPolicy.fixedSeries),
    );
    return ContainsImmutable.addContainsImmutable(
      partiallyCombinedContainsImmutable,
      ContainsImmutable.transactionOutputAddress(groupPolicy.registrationUtxo),
    );
  }

  //TODO: determine how to work with protobuf enums
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static fungibility(fungibilityType: any) {
    return ContainsImmutable.int(fungibilityType.value);
  }

  //TODO: determine how to work with protobuf enums
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static quantityDescriptor(quantityDescriptor: any) {
    return ContainsImmutable.int(quantityDescriptor.value);
  }

  static seriesPolicyEvent(seriesPolicy: Event_SeriesPolicy) {
    const combinedIntContainsImmutable = ContainsImmutable.addContainsImmutable(
      ContainsImmutable.string(seriesPolicy.label),
      ContainsImmutable.int(seriesPolicy.tokenSupply.value),
    );
    const combinedIntContainsImmutable2 = ContainsImmutable.addContainsImmutable(
      combinedIntContainsImmutable,
      ContainsImmutable.transactionOutputAddress(seriesPolicy.registrationUtxo),
    );
    const combinedIntContainsImmutable3 = ContainsImmutable.addContainsImmutable(
      combinedIntContainsImmutable2,
      ContainsImmutable.fungibility(seriesPolicy.fungibility),
    );
    return ContainsImmutable.addContainsImmutable(
      combinedIntContainsImmutable3,
      ContainsImmutable.quantityDescriptor(seriesPolicy.quantityDescriptor),
    );
  }

  static apply(t): ContainsImmutable {
    if (t instanceof ContainsImmutable) {
      return t;
    }
    if (t instanceof ImmutableBytes) {
      return new ContainsImmutable(t);
    }
    if (t instanceof Lock) {
      return ContainsImmutable.lock(t);
    }
  }
}
