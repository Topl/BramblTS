import { ImmutableBytes, IoTransaction, SignableBytes, type SpentTransactionOutput } from 'topl_common';

export default class ContainsSignable {
  readonly signableBytes: SignableBytes;

  constructor (signableBytes: SignableBytes) {
    this.signableBytes = signableBytes;
  }

  static empty (): ContainsSignable {
    return new ContainsSignable(new SignableBytes());
  }

  static immutable (bytes: ImmutableBytes): ContainsSignable {
    return new ContainsSignable(new SignableBytes(bytes));
  }

  static ioTransaction (iotx: IoTransaction): ContainsSignable {
    /// Strips the proofs from a SpentTransactionOutput.
    /// This is needed because the proofs are not part of the transaction's signable bytes
    function stripInput (stxo: SpentTransactionOutput): SpentTransactionOutput {
      const stripped = stxo.clone();

      const attestation = stxo.attestation.value;
      if (attestation.case === 'predicate') {
        stripped.attestation.value.value.responses = [];
      } else if (attestation.case === 'image') {
        stripped.attestation.value.value.responses = [];
      } else if (attestation.case === 'commitment') {
        stripped.attestation.value.value.responses = [];
      }
      return stripped;
    }

    const updatedIotx = iotx.clone();
    updatedIotx.inputs = iotx.inputs.map(stripInput);
    // return ContainsSignable.immutable(ContainsImmutable.apply(updatedInputs).immutableBytes);
    return ContainsSignable.immutable(updatedIotx.immutableBytes());
  }
}


/// experimental extensions via typescript module augmentation
declare module 'topl_common' {
  interface IoTransaction {
    signable?(): SignableBytes; // marked optional to not mess up with type identification
  }
  interface ImmutableBytes {
    signable?(): SignableBytes;
  }
}
IoTransaction.prototype.signable = function () {
  return ContainsSignable.ioTransaction(this).signableBytes;
};

ImmutableBytes.prototype.signable = function () {
  return ContainsSignable.ioTransaction(this).signableBytes;
};
