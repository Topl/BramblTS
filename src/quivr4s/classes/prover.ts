import { blake2b256 } from 'hashlib';
import { Int8Array } from 'typedarray';
import { Proof, Proof_Locked, Proof_Digest, Proof_DigitalSignature, Proof_HeightRange, Proof_TickRange, Proof_ExactMatch, Proof_LessThan, Proof_GreaterThan, Proof_EqualTo, Proof_Threshold, Proof_Not, Proof_And, Proof_Or } from 'proof.pb';
import { TxBind } from 'shared.pb';
import { Tokens } from 'tokens';

/// Provers create proofs that are bound to the transaction which executes the proof.
///
/// This provides a generic way to map all computations (single-step or sigma-protocol)
/// into a Fiat-Shamir heuristic if the bind that is used here is unique.
class Prover {
    /// creates a [TxBind] object for the given [tag] and [message]
    /// [tag] is an identifier of the Operation
    /// [message] unique bytes from a transaction that will be bound to the proof
    /// @return [TxBind] / array of bytes that is similar to a "signature" for the proof
    private static _blake2b56ToTxBind(tag: string, message: SignableBytes): TxBind {
        const m = new Uint8Array([...Buffer.from(tag, 'utf8'), ...message.value]);
        const h = blake2b256(m);
        return { value: h };
    }

    public static lockedProver(): Proof {
        return { locked: new Proof_Locked() };
    }

    public static digestProver(preimage: Preimage, message: SignableBytes): Proof {
        return {
            digest: new Proof_Digest({
                transactionBind: Prover._blake2b56ToTxBind(Tokens.digest, message),
                preimage,
            }),
        };
    }

    public static signatureProver(witness: Witness, message: SignableBytes): Proof {
        return {
            digitalSignature: new Proof_DigitalSignature({
                transactionBind: Prover._blake2b56ToTxBind(Tokens.digitalSignature, message),
                witness,
            }),
        };
    }

    public static heightProver(message: SignableBytes): Proof {
        return {
            heightRange: new Proof_HeightRange({
                transactionBind: Prover._blake2b56ToTxBind(Tokens.heightRange, message),
            }),
        };
    }

    public static tickProver(message: SignableBytes): Proof {
        return {
            tickRange: new Proof_TickRange({
                transactionBind: Prover._blake2b56ToTxBind(Tokens.tickRange, message),
            }),
        };
    }

    public static exactMatchProver(message: SignableBytes, compareTo: Int8Array): Proof {
        return {
            exactMatch: new Proof_ExactMatch({
                transactionBind: Prover._blake2b56ToTxBind(Tokens.exactMatch, message),
            }),
        };
    }

    public static lessThanProver(message: SignableBytes): Proof {
        return {
            lessThan: new Proof_LessThan({
                transactionBind: Prover._blake2b56ToTxBind(Tokens.lessThan, message),
            }),
        };
    }

    public static greaterThanProver(message: SignableBytes): Proof {
        return {
            greaterThan: new Proof_GreaterThan({
                transactionBind: Prover._blake2b56ToTxBind(Tokens.greaterThan, message),
            }),
        };
    }

    public static equalToProver(location: string, message: SignableBytes): Proof {
        return {
            equalTo: new Proof_EqualTo({
                transactionBind: Prover._blake2b56ToTxBind(Tokens.equalTo, message),
            }),
        };
    }

    public static thresholdProver(responses: Proof[], message: SignableBytes): Proof {
        return {
            threshold: new Proof_Threshold({
                transactionBind: Prover._blake2b56ToTxBind(Tokens.threshold, message),
                responses,
            }),
        };
    }

    public static notProver(proof: Proof, message: SignableBytes): Proof {
        return {
            not: new Proof_Not({
                transactionBind: Prover._blake2b56ToTxBind(Tokens.not, message),
                proof,
            }),
        };
    }

    public static andProver(left: Proof, right: Proof, message: SignableBytes): Proof {
        return {
            and: new Proof_And({
                transactionBind: Prover._blake2b56ToTxBind(Tokens.and, message),
                left,
                right,
            }),
        };
    }

    public static orProver(left: Proof, right: Proof, message: SignableBytes): Proof {
        return {
            or: new Proof_Or({
                transactionBind: Prover._blake2b56ToTxBind(Tokens.or, message),
                left,
                right,
            }),
        };
    }
}