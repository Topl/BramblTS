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
  Proof_Not,
  Proof_Or,
  Proof_Threshold,
  Proof_TickRange,
  SignableBytes,
  TxBind,
  Witness
} from 'topl_common';
import { Tokens } from '../../tokens.js';
import { blake2b256 } from '@/crypto/crypto.js';

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
    const merge = new Uint8Array([...Buffer.from(tag, 'utf8'), ...message.value]);
    const h = blake2b256.hash(merge);
    return new TxBind({ value: h });
  }

  public static lockedProver (): Proof {
    return new Proof({ value: { case: 'locked', value: new Proof_Locked() } });
  }

  public static digestProver (preimage: Preimage, message: SignableBytes): Proof {
    return new Proof({
      value: {
        case: 'digest',
        value: new Proof_Digest({ preimage, transactionBind: this._blake2b56ToTxBind(Tokens.digest, message) })
      }
    });
  }

  public static signatureProver (witness: Witness, message: SignableBytes): Proof {
    return new Proof({
      value: {
        case: 'digitalSignature',
        value: new Proof_DigitalSignature({
          witness,
          transactionBind: this._blake2b56ToTxBind(Tokens.digitalSignature, message)
        })
      }
    });
  }

  public static heightProver (message: SignableBytes): Proof {
    return new Proof({
      value: {
        case: 'heightRange',
        value: new Proof_HeightRange({ transactionBind: this._blake2b56ToTxBind(Tokens.heightRange, message) })
      }
    });
  }

  public static tickProver (message: SignableBytes): Proof {
    return new Proof({
      value: {
        case: 'tickRange',
        value: new Proof_TickRange({ transactionBind: this._blake2b56ToTxBind(Tokens.tickRange, message) })
      }
    });
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public static exactMatchProver (message: SignableBytes, compareTo: Int8Array): Proof {
    return new Proof({
      value: {
        case: 'exactMatch',
        value: new Proof_ExactMatch({ transactionBind: this._blake2b56ToTxBind(Tokens.exactMatch, message) })
      }
    });
  }

  public static lessThanProver (message: SignableBytes): Proof {
    return new Proof({
      value: {
        case: 'lessThan',
        value: new Proof_LessThan({ transactionBind: this._blake2b56ToTxBind(Tokens.lessThan, message) })
      }
    });
  }

  public static greaterThanProver (message: SignableBytes): Proof {
    return new Proof({
      value: {
        case: 'greaterThan',
        value: new Proof_GreaterThan({ transactionBind: this._blake2b56ToTxBind(Tokens.greaterThan, message) })
      }
    });
  }

  public static equalToProver (location: string, message: SignableBytes): Proof {
    return new Proof({
      value: {
        case: 'equalTo',
        value: new Proof_EqualTo({ transactionBind: this._blake2b56ToTxBind(Tokens.equalTo, message) })
      }
    });
  }

  public static thresholdProver (responses: Proof[], message: SignableBytes): Proof {
    return new Proof({
      value: {
        case: 'threshold',
        value: new Proof_Threshold({ responses, transactionBind: this._blake2b56ToTxBind(Tokens.threshold, message) })
      }
    });
  }

  public static notProver (proof: Proof, message: SignableBytes): Proof {
    return new Proof({
      value: {
        case: 'not',
        value: new Proof_Not({ proof, transactionBind: this._blake2b56ToTxBind(Tokens.not, message) })
      }
    });
  }

  public static andProver (left: Proof, right: Proof, message: SignableBytes): Proof {
    return new Proof({
      value: {
        case: 'and',
        value: new Proof_And({ left, right, transactionBind: this._blake2b56ToTxBind(Tokens.and, message) })
      }
    });
  }

  public static orProver (left: Proof, right: Proof, message: SignableBytes): Proof {
    return new Proof({
      value: {
        case: 'or',
        value: new Proof_Or({ left, right, transactionBind: this._blake2b56ToTxBind(Tokens.or, message) })
      }
    });
  }
}
