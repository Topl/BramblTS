import { blake2b } from 'blakejs';
import {
  Preimage,
  Proof,
  Proof_And,
  Proof_Digest,
  Proof_DigitalSignature,
  Proof_EqualTo,
  Proof_ExactMatch,
  Proof_GreaterThan,
  Proof_HeightRange,
  Proof_LessThan,
  Proof_Locked,
  Proof_Or,
  Proof_Threshold,
  Proof_TickRange,
  SignableBytes,
  TxBind,
  Witness
} from 'topl_common';
import { Tokens } from './tokens.js';

/// Provers create proofs that are bound to the transaction which executes the proof.
///
/// This provides a generic way to map all computations (single-step or sigma-protocol)
/// into a Fiat-Shamir heuristic if the bind that is used here is unique.
export class Prover {
  /// creates a [TxBind] object for the given [tag] and [message]
  /// [tag] is an identifier of the Operation
  /// [message] unique bytes from a transaction that will be bound to the proof
  /// @return [TxBind] / array of bytes that is similar to a "signature" for the proof
  private static _blake2b56ToTxBind (tag: string, message: SignableBytes): TxBind {
    const encoder = new TextEncoder();
    const m = new Uint8Array([...encoder.encode(tag), ...message.value]);
    const h = blake2b(m);
    return new TxBind({ value: h });
  }

  public static lockedProver (): Proof {
    return new Proof({ locked: new Proof_Locked() });
  }

  public static digestProver (preimage: Preimage, message: SignableBytes): Proof {
    return new Proof({
      digest: new Proof_Digest({ preimage, transactionBind: this._blake2b56ToTxBind(Tokens.digest, message) })
    });
  }

  public static signatureProver (witness: Witness, message: SignableBytes): Proof {
    return new Proof({
      digitalSignature: new Proof_DigitalSignature({
        witness,
        transactionBind: this._blake2b56ToTxBind(Tokens.digitalSignature, message)
      })
    });
  }

  public static heightProver (message: SignableBytes): Proof {
    return new Proof({
      heightRange: new Proof_HeightRange({ transactionBind: this._blake2b56ToTxBind(Tokens.heightRange, message) })
    });
  }

  public static tickProver (message: SignableBytes): Proof {
    return new Proof({
      tickRange: new Proof_TickRange({ transactionBind: this._blake2b56ToTxBind(Tokens.tickRange, message) })
    });
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public static exactMatchProver (message: SignableBytes, compareTo: Int8Array): Proof {
    return new Proof({
      exactMatch: new Proof_ExactMatch({ transactionBind: this._blake2b56ToTxBind(Tokens.exactMatch, message) })
    });
  }

  public static lessThanProver (message: SignableBytes): Proof {
    return new Proof({
      lessThan: new Proof_LessThan({ transactionBind: this._blake2b56ToTxBind(Tokens.lessThan, message) })
    });
  }

  public static greaterThanProver (message: SignableBytes): Proof {
    return new Proof({
      greaterThan: new Proof_GreaterThan({ transactionBind: this._blake2b56ToTxBind(Tokens.greaterThan, message) })
    });
  }

  public static equalToProver (location: string, message: SignableBytes): Proof {
    return new Proof({
      equalTo: new Proof_EqualTo({ transactionBind: this._blake2b56ToTxBind(Tokens.equalTo, message) })
    });
  }

  public static thresholdProver (responses: Proof[], message: SignableBytes): Proof {
    return new Proof({
      threshold: new Proof_Threshold({ responses, transactionBind: this._blake2b56ToTxBind(Tokens.equalTo, message) })
    });
  }

  public static notProver (responses: Proof[], message: SignableBytes): Proof {
    return new Proof({
      threshold: new Proof_Threshold({ responses, transactionBind: this._blake2b56ToTxBind(Tokens.not, message) })
    });
  }

  public static andProver (left: Proof, right: Proof, message: SignableBytes): Proof {
    return new Proof({
      and: new Proof_And({ left, right, transactionBind: this._blake2b56ToTxBind(Tokens.and, message) })
    });
  }

  public static orProver (left: Proof, right: Proof, message: SignableBytes): Proof {
    return new Proof({
      or: new Proof_Or({ left, right, transactionBind: this._blake2b56ToTxBind(Tokens.or, message) })
    });
  }
}
