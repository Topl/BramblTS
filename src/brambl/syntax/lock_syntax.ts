import { ContainsEvidence, Lock, LockAddress, LockId } from 'topl_common';

export class LockSyntax {
  static lockAsLockSyntaxOps (lock: Lock): LockSyntaxOps {
    return new LockSyntaxOps(lock);
  }

  static predicateLockAsLockSyntaxOps (lock: Lock.Predicate): PredicateLockSyntaxOps {
    return new PredicateLockSyntaxOps(lock);
  }
}

export class LockSyntaxOps {
  lock: Lock;

  constructor (lock: Lock) {
    this.lock = lock;
  }

  lockAddress (network: number, ledger: number): LockAddress {
    return new LockAddress(network, ledger, new LockId(ContainsEvidence.sizedEvidence(this.lock).digest.value));
  }
}

export class PredicateLockSyntaxOps {
  lock: Lock.Predicate;

  constructor (lock: Lock.Predicate) {
    this.lock = lock;
  }

  lockAddress (network: number, ledger: number): LockAddress {
    return new LockAddress(
      network,
      ledger,
      new LockId(ContainsEvidence.sizedEvidence(new Lock().withPredicate(this.lock)).digest.value)
    );
  }
}
