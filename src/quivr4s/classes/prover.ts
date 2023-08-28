// import { blake2b256 } from 'hashlib';
// import { Int8Array } from 'typedarray';
// import { Proof, Proof_Locked, Proof_Digest, Proof_DigitalSignature, Proof_HeightRange, Proof_TickRange, Proof_ExactMatch, Proof_LessThan, Proof_GreaterThan, Proof_EqualTo, Proof_Threshold, Proof_Not, Proof_And, Proof_Or } from 'proof.pb';
// import { TxBind } from 'shared.pb';
// import { Tokens } from 'tokens';
import * as shared from '../../../proto/quivr/models/shared.js';
import * as proof from '../../../proto/quivr/models/proof.js';
import { Tokens } from './tokens.js';
import { blake2b } from 'blakejs';


/// Provers create proofs that are bound to the transaction which executes the proof.
///
/// This provides a generic way to map all computations (single-step or sigma-protocol)
/// into a Fiat-Shamir heuristic if the bind that is used here is unique.
export class Prover {
    /// creates a [TxBind] object for the given [tag] and [message]
    /// [tag] is an identifier of the Operation
    /// [message] unique bytes from a transaction that will be bound to the proof
    /// @return [TxBind] / array of bytes that is similar to a "signature" for the proof
    private static _blake2b56ToTxBind(tag: string, message: shared.quivr.models.SignableBytes): shared.quivr.models.TxBind {
        const encoder = new TextEncoder();
        const m = new Uint8Array([...encoder.encode(tag), ...message.value]);
        const h = blake2b(m);
        return new shared.quivr.models.TxBind({ value: h });
    }

    public static lockedProver(): proof.quivr.models.Proof {
        return new proof.quivr.models.Proof({ locked: new proof.quivr.models.Proof.Locked() });
    }

    public static digestProver(preimage: shared.quivr.models.Preimage, message: shared.quivr.models.SignableBytes): proof.quivr.models.Proof {
        return new proof.quivr.models.Proof({ digest: new proof.quivr.models.Proof.Digest({ preimage, transactionBind: this._blake2b56ToTxBind(Tokens.digest, message) }) });

    }

    public static signatureProver(witness: shared.quivr.models.Witness, message: shared.quivr.models.SignableBytes): proof.quivr.models.Proof {
        return new proof.quivr.models.Proof({ digitalSignature: new proof.quivr.models.Proof.DigitalSignature({ witness, transactionBind: this._blake2b56ToTxBind(Tokens.digitalSignature, message) }) });

    }

    public static heightProver(message: shared.quivr.models.SignableBytes): proof.quivr.models.Proof {
        return new proof.quivr.models.Proof({ heightRange: new proof.quivr.models.Proof.HeightRange({ transactionBind: this._blake2b56ToTxBind(Tokens.heightRange, message) }) });

    }

    public static tickProver(message: shared.quivr.models.SignableBytes): proof.quivr.models.Proof {
        return new proof.quivr.models.Proof({ tickRange: new proof.quivr.models.Proof.TickRange({ transactionBind: this._blake2b56ToTxBind(Tokens.tickRange, message) }) });

    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    public static exactMatchProver(message: shared.quivr.models.SignableBytes, compareTo: Int8Array): proof.quivr.models.Proof {
        return new proof.quivr.models.Proof({ exactMatch: new proof.quivr.models.Proof.ExactMatch({ transactionBind: this._blake2b56ToTxBind(Tokens.exactMatch, message) }) });

    }

    public static lessThanProver(message: shared.quivr.models.SignableBytes): proof.quivr.models.Proof {
        return new proof.quivr.models.Proof({ lessThan: new proof.quivr.models.Proof.LessThan({ transactionBind: this._blake2b56ToTxBind(Tokens.lessThan, message) }) });

    }

    public static greaterThanProver(message: shared.quivr.models.SignableBytes): proof.quivr.models.Proof {
        return new proof.quivr.models.Proof({ greaterThan: new proof.quivr.models.Proof.GreaterThan({ transactionBind: this._blake2b56ToTxBind(Tokens.greaterThan, message) }) });

    }

    public static equalToProver(location: string, message: shared.quivr.models.SignableBytes): proof.quivr.models.Proof {
        return new proof.quivr.models.Proof({ equalTo: new proof.quivr.models.Proof.EqualTo({ transactionBind: this._blake2b56ToTxBind(Tokens.equalTo, message) }) });

    }

    public static thresholdProver(responses: proof.quivr.models.Proof[], message: shared.quivr.models.SignableBytes): proof.quivr.models.Proof {
        return new proof.quivr.models.Proof({ threshold: new proof.quivr.models.Proof.Threshold({ responses, transactionBind: this._blake2b56ToTxBind(Tokens.equalTo, message) }) });

    }

    public static notProver(responses: proof.quivr.models.Proof[], message: shared.quivr.models.SignableBytes): proof.quivr.models.Proof {
        return new proof.quivr.models.Proof({ threshold: new proof.quivr.models.Proof.Threshold({ responses, transactionBind: this._blake2b56ToTxBind(Tokens.not, message) }) });
    }

    public static andProver(left: proof.quivr.models.Proof, right: proof.quivr.models.Proof, message: shared.quivr.models.SignableBytes): proof.quivr.models.Proof {
        return new proof.quivr.models.Proof({ and: new proof.quivr.models.Proof.And({ left, right, transactionBind: this._blake2b56ToTxBind(Tokens.and, message) }) });

    }

    public static orProver(left: proof.quivr.models.Proof, right: proof.quivr.models.Proof, message: shared.quivr.models.SignableBytes): proof.quivr.models.Proof {
        return new proof.quivr.models.Proof({ or: new proof.quivr.models.Proof.Or({ left, right, transactionBind: this._blake2b56ToTxBind(Tokens.or, message) }) });

    }
}