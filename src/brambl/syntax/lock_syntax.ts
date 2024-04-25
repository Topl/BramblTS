import { Lock, Lock_Predicate, LockAddress, LockId } from 'topl_common';
import { ContainsEvidence } from '../common/contains_evidence.js';

export class LockSyntaxOps {
  lock: Lock;

  constructor (lock: Lock) {
    this.lock = lock;
  }

  lockAddress (network: number, ledger: number): LockAddress {
    const evidence = new LockId(ContainsEvidence.blake2bEvidenceFromImmutable(this.lock).evidence);
    const digest = evidence.value;
    const lockId = new LockId({ value: digest });
    return new LockAddress({ network: network, ledger: ledger, id: lockId });
  }
}

export class PredicateLockSyntaxOps {
  lock: Lock_Predicate;

  constructor (lock: Lock_Predicate) {
    this.lock = lock;
  }

  lockAddress (network: number, ledger: number): LockAddress {
    const predicate = new Lock({ value: this.lock });
    const evidence = new LockId(ContainsEvidence.blake2bEvidenceFromImmutable(predicate).evidence);
    const digest = evidence.value;
    const lockId = new LockId({ value: digest });
    return new LockAddress({ network: network, ledger: ledger, id: lockId });
  }
}
