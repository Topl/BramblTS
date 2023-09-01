
import { blake2b } from 'blakejs';
import { QuivrResult, quivrEvaluationAuthorizationFailure } from '../common/quivr_result.js';
import { DigestVerification, Message, Proof, Proof_Digest, Proof_DigitalSignature, Proof_HeightRange, Proposition, Proposition_Digest, Proposition_DigitalSignature, Proposition_HeightRange, SignatureVerification, TxBind } from '../common/types.js';
import { DynamicContext } from '../runtime/dynamic_context.js';
import { ValidationError } from '../runtime/quivr_runtime_error.js';
import { either } from 'fp-ts'
import { arraysEqual } from '../utils/list_utils.js';
import { Tokens } from './tokens.js';

export class Verifier {
    /// Will return [QuivrResult] Left => [QuivrRuntimeError.messageAuthorizationFailure] if the proof is invalid.
    static _evaluateBlake2b256Bind(
        tag: string,
        proof: Proof,
        proofTxBind: TxBind,
        context: DynamicContext,
    ): QuivrResult<boolean> {
        const sb = context.signableBytes;
        const encoder = new TextEncoder();

        const merge = new Uint8Array([...encoder.encode(tag), ...sb.value.toUint8List()]);
        const verifierTxBind = blake2b(merge);
        const result = arraysEqual(verifierTxBind, proofTxBind.value);


        return result ? either.left(ValidationError.messageAuthorizationFailure({ name: 'QQQQ', message: 'QQQQ' })) : either.right(result);
    }



    static evaluateResult(
        messageResult: QuivrResult<boolean>,
        evalResult: QuivrResult<boolean>,
        {
            proposition,
            proof,
        }: {
            proposition: Proposition;
            proof: Proof;
        }
    ): QuivrResult<boolean> {
        if (messageResult._tag === 'Right' && evalResult._tag === 'Right') {
            return either.right(true);

        } else {
            return quivrEvaluationAuthorizationFailure(proof, proposition);
        }

    }



    private lockedVerifier(
    ): QuivrResult<boolean> {
        return either.left(ValidationError.lockedPropositionIsUnsatisfiable({
            name: 'QQQQ',
            message: 'QQQQ',
        }));
    }

    static verifyDigest(
        proposition: Proposition_Digest,
        proof: Proof_Digest,
        context: DynamicContext,
    ): QuivrResult<boolean> {

        const wrappedProposition: Proposition = new Proposition({ digest: new Proposition.Digest({ digest: proposition }) });
        const wrappedProof: Proof = new Proof({ digest: new Proof.Digest({ preimage: proof.preimage, transactionBind: proof.transactionBind, }) });

        const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.digest, wrappedProof, proof.transactionBind, context);

        either.flatMap

        if (messageResult._tag === "Left") return messageResult;

        const evalResult = context.digestVerify(
            proposition.routine, new DigestVerification({ digest: proposition.digest, preimage: proof.preimage }));

        return Verifier.evaluateResult(
            messageResult,
            evalResult,
            {
                proposition: wrappedProposition,
                proof: wrappedProof,
            }
        );
    }


    static verifySignature(
        proposition: Proposition_DigitalSignature,
        proof: Proof_DigitalSignature,
        context: DynamicContext,
    ): QuivrResult<boolean> {


        const wrappedProposition: Proposition = new Proposition({ digitalSignature: new Proposition.DigitalSignature({ routine: proposition.routine, verificationKey: proposition.verificationKey, }) });
        const wrappedProof: Proof = new Proof({ digitalSignature: new Proof.DigitalSignature({ witness: proof.witness, transactionBind: proof.transactionBind, }) });

        const messageResult =
            Verifier._evaluateBlake2b256Bind(Tokens.digitalSignature, wrappedProof, proof.transactionBind, context);

        if (messageResult._tag === "Left") return messageResult;

        const signedMessage = context.signableBytes;
        const verification = new SignatureVerification({
            verificationKey: proposition.verificationKey,
            signature: proof.witness,
            message: new Message({ value: signedMessage.value.toList() })
        });

        const evalResult = context.signatureVerify(proposition.routine, verification);

        return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
    }

    static verifyHeightRange(
        proposition: Proposition_HeightRange,
        proof: Proof_HeightRange,
        context: DynamicContext,
    ): QuivrResult<boolean> {

        const wrappedProposition: Proposition = new Proposition({ heightRange: new Proposition.HeightRange({ chain: proposition.chain, max: proposition.max, min: proposition.min }) });
        const wrappedProof: Proof = new Proof({ heightRange: new Proof.HeightRange({ transactionBind: proof.transactionBind, }) });


        const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.heightRange, wrappedProof, proof.transactionBind, context);

        if (messageResult._tag === 'Left') return messageResult;

        const x = context.heightOf(proposition.chain);
        const chainHeight: QuivrResult<number> =
            x != null ? either.right(x) : quivrEvaluationAuthorizationFailure<number>(proof, proposition);

        if (chainHeight._tag === 'Left') return either.left(chainHeight.left);

        const height = chainHeight.right!;

        const evalResult: QuivrResult<boolean> = (proposition.max >= height) && (proposition.min <= height)
            ? either.right(true)
            : quivrEvaluationAuthorizationFailure(proof, proposition);

        return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
    }

}

