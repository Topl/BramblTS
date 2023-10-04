
import { blake2b } from 'blakejs';
import { QuivrResult, quivrEvaluationAuthorizationFailure } from '../common/quivr_result.js';
import { DigestVerification, Message, Proof, Proof_And, Proof_Digest, Proof_DigitalSignature, Proof_EqualTo, Proof_ExactMatch, Proof_GreaterThan, Proof_HeightRange, Proof_LessThan, Proof_Not, Proof_Or, Proof_Threshold, Proof_TickRange, Proposition, Proposition_And, Proposition_Digest, Proposition_DigitalSignature, Proposition_EqualTo, Proposition_ExactMatch, Proposition_GreaterThan, Proposition_HeightRange, Proposition_LessThan, Proposition_Not, Proposition_Or, Proposition_Threshold, Proposition_TickRange, SignatureVerification, TxBind } from '../common/types.js';
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

        const merge = new Uint8Array([...encoder.encode(tag), ...sb.value]);
        const verifierTxBind = blake2b(merge);
        const result = arraysEqual(verifierTxBind, proofTxBind.value);


        return result ? either.left(ValidationError.messageAuthorizationFailure({ name: 'Blake2b256Bind', message: 'Error in evaluating Blake2b256Bind' })) : either.right(result);
    }



    static evaluateResult(
        messageResult: QuivrResult<boolean>,
        evalResult: QuivrResult<unknown>,
        {
            proposition,
            proof,
        }: {
            proposition: Proposition;
            proof: Proof;
        }
    ): QuivrResult<boolean> {
        if (messageResult._tag === 'Right' && evalResult._tag === 'Right') {
            return (true);

        } else {
            return quivrEvaluationAuthorizationFailure(proof, proposition);
        }

    }



    static verifyLocked(
    ): QuivrResult<boolean> {
        return either.left(ValidationError.lockedPropositionIsUnsatisfiable({
            name: 'Locked',
            message: 'Locked proposition is unsatisfiable',
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
            message: new Message({ value: signedMessage.value })
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

    static verifyTickRange(
        proposition: Proposition_TickRange,
        proof: Proof_TickRange,
        context: DynamicContext,
    ): QuivrResult<boolean> {
        const wrappedProposition: Proposition = new Proposition({ tickRange: new Proposition.TickRange({ max: proposition.max, min: proposition.min }) });
        const wrappedProof: Proof = new Proof({ tickRange: new Proof.TickRange({ transactionBind: proof.transactionBind, }) });

        const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.tickRange, wrappedProof, proof.transactionBind, context);

        if (messageResult._tag === 'Left') return messageResult;

        if (context.currentTick < proposition.min || context.currentTick > proposition.max) {
            return quivrEvaluationAuthorizationFailure(proof, proposition);
        }
        const tick = context.currentTick;

        const evalResult: QuivrResult<boolean> = ((proposition.min <= tick) && (tick <= proposition.max))
            ? either.right(true)
            : quivrEvaluationAuthorizationFailure(proof, proposition);

        return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
    }

    static verifyExactMatch(
        proposition: Proposition_ExactMatch,
        proof: Proof_ExactMatch,
        context: DynamicContext,
    ): QuivrResult<boolean> {
        const wrappedProposition: Proposition = new Proposition({ exactMatch: new Proposition.ExactMatch({ compareTo: proposition.compareTo, location: proposition.location }) });
        const wrappedProof: Proof = new Proof({ exactMatch: new Proof.ExactMatch({ transactionBind: proof.transactionBind, }) });

        const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.exactMatch, wrappedProof, proof.transactionBind, context);

        if (messageResult._tag === 'Left') return messageResult;

        const evalResult: QuivrResult<boolean> = context.exactMatch(proposition.location, proposition.compareTo) ? either.right(true) : quivrEvaluationAuthorizationFailure(proof, proposition);

        return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
    }

    static verifyLessThan(
        proposition: Proposition_LessThan,
        proof: Proof_LessThan,
        context: DynamicContext
    ): QuivrResult<boolean> {
        const wrappedProposition: Proposition = new Proposition({ exactMatch: new Proposition.ExactMatch({ compareTo: proposition.compareTo, location: proposition.location }) });
        const wrappedProof: Proof = new Proof({ exactMatch: new Proof.ExactMatch({ transactionBind: proof.transactionBind, }) });

        const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.lessThan, wrappedProof, proof.transactionBind, context);

        if (messageResult._tag === 'Left') return messageResult;

        const evalResult: QuivrResult<boolean> = context.lessThan(proposition.location, proposition.compareTo.value.toBigInt) ? either.right(true) : quivrEvaluationAuthorizationFailure(proof, proposition);

        return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
    }

    static verifyGreaterThan(
        proposition: Proposition_GreaterThan,
        proof: Proof_GreaterThan,
        context: DynamicContext
    ): QuivrResult<boolean> {
        const wrappedProposition: Proposition = new Proposition({ greaterThan: new Proposition.GreaterThan({ compareTo: proposition.compareTo, location: proposition.location }) });
        const wrappedProof: Proof = new Proof({ greaterThan: new Proof.GreaterThan({ transactionBind: proof.transactionBind, }) });

        const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.greaterThan, wrappedProof, proof.transactionBind, context);

        if (messageResult._tag === 'Left') return messageResult;

        const evalResult: QuivrResult<boolean> = context.greaterThan(proposition.location, proposition.compareTo.value.toBigInt) ? either.right(true) : quivrEvaluationAuthorizationFailure(proof, proposition);

        return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
    }


    static verifyEqualTo(
        proposition: Proposition_EqualTo,
        proof: Proof_EqualTo,
        context: DynamicContext
    ): QuivrResult<boolean> {
        const wrappedProposition: Proposition = new Proposition({ equalTo: new Proposition.EqualTo({ compareTo: proposition.compareTo, location: proposition.location }) });
        const wrappedProof: Proof = new Proof({ equalTo: new Proof.EqualTo({ transactionBind: proof.transactionBind, }) });

        const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.equalTo, wrappedProof, proof.transactionBind, context);

        if (messageResult._tag === 'Left') return messageResult;

        const evalResult: QuivrResult<boolean> = context.equalTo(proposition.location, proposition.compareTo.value.toBigInt) ? either.right(true) : quivrEvaluationAuthorizationFailure(proof, proposition);

        return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
    }

    static async verifyThreshold(
        proposition: Proposition_Threshold,
        proof: Proof_Threshold,
        context: DynamicContext
    ): Promise<QuivrResult<boolean>> {
        const wrappedProposition: Proposition = new Proposition({ threshold: new Proposition.Threshold({ challenges: proposition.challenges, threshold: proposition.threshold }) });
        const wrappedProof: Proof = new Proof({ threshold: new Proof.Threshold({ transactionBind: proof.transactionBind, responses: proof.responses }) });

        const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.threshold, wrappedProof, proof.transactionBind, context);

        if (messageResult._tag === 'Left') return Promise.reject(either.left(messageResult.left));

        // Initialize as true;
        let evalResult: QuivrResult<boolean> = either.right(false);

        if (proposition.threshold == 0) {
            evalResult = either.right(true);
        } else if ((proposition.threshold > proposition.challenges.length ||
            proof.responses.length === 0 ||
            proof.responses.length != proposition.challenges.length)) {
            evalResult = quivrEvaluationAuthorizationFailure(proof, proposition);
        } else {
            let successCount: number = 0;
            for (let i = 0; i < proposition.challenges.length && successCount < proposition.threshold; i++) {
                const challenge = proposition.challenges[i];
                const response = proof.responses[i];
                const verifyResult = await Verifier.verify(challenge, response, context);
                if (verifyResult._tag === 'Right') {
                    successCount++;
                }
            }
            if (successCount < proposition.threshold) {
                evalResult = quivrEvaluationAuthorizationFailure(proof, proposition);
            }
        }

        return Promise.resolve(Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof }));
    }

    static async verifyNot(
        proposition: Proposition_Not,
        proof: Proof_Not,
        context: DynamicContext
    ): Promise<QuivrResult<boolean>> {
        const wrappedProposition: Proposition = new Proposition({ not: new Proposition.Not({ proposition: proposition.proposition }) });
        const wrappedProof: Proof = new Proof({ not: new Proof.Not({ transactionBind: proof.transactionBind, proof: proof.proof }) });

        const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.not, wrappedProof, proof.transactionBind, context);
        if (messageResult._tag === 'Left') return Promise.reject(either.left(messageResult.left));

        const evalResult = await Verifier.verify(proposition.proposition, proof.proof, context);

        const beforeReturn: QuivrResult<boolean> =
            Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });

        return beforeReturn._tag === 'Right'
            ? quivrEvaluationAuthorizationFailure(proof, proposition)
            : either.right(true);
    }

    static async verifyAnd(
        proposition: Proposition_And,
        proof: Proof_And,
        context: DynamicContext
    ): Promise<QuivrResult<boolean>> {
        const wrappedProposition: Proposition = new Proposition({ and: new Proposition.And({ left: proposition.left, right: proposition.right }) });
        const wrappedProof: Proof = new Proof({ not: new Proof.Not({ transactionBind: proof.transactionBind, proof: proof.left }) });

        const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.and, wrappedProof, proof.transactionBind, context);
        if (messageResult._tag === 'Left') return Promise.reject(either.left(messageResult.left));

        const leftResult = await Verifier.verify(proposition.left, proof.left, context);
        if (leftResult._tag === 'Left') return leftResult;

        const rightResult = await Verifier.verify(proposition.right, proof.right, context);
        if (rightResult._tag === 'Left') return rightResult;

        // We're not checking the value of right as it's existence is enough to satisfy this condition
        if (leftResult._tag === 'Right' && rightResult._tag === 'Right') return either.right(true);

        return quivrEvaluationAuthorizationFailure(wrappedProposition, wrappedProof);
    }

    static async verifyOr(
        proposition: Proposition_Or,
        proof: Proof_Or,
        context: DynamicContext
    ): Promise<QuivrResult<boolean>> {
        // const wrappedProposition: Proposition = new Proposition({ and: new Proposition.And({ left: proposition.left, right: proposition.right }) });
        const wrappedProof: Proof = new Proof({ not: new Proof.Not({ transactionBind: proof.transactionBind, proof: proof.left }) });

        const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.or, wrappedProof, proof.transactionBind, context);
        if (messageResult._tag === 'Left') return Promise.reject(either.left(messageResult.left));

        const leftResult = await Verifier.verify(proposition.left, proof.left, context);
        if (leftResult._tag === 'Right') return either.right(true);

        const rightResult = await Verifier.verify(proposition.right, proof.right, context);
        return rightResult;
    }

    static async verify(
        proposition: Proposition,
        proof: Proof,
        context: DynamicContext
    ): Promise<QuivrResult<boolean>> {
        if (proposition.has_locked && proposition.has_locked) {
            return Verifier.verifyLocked();
        } else if (proposition.has_digest && proof.has_digest) {
            return Verifier.verifyDigest(proposition.digest, proof.digest, context);
        } else if (proposition.has_digitalSignature && proof.has_digitalSignature) {
            return Verifier.verifySignature(proposition.digitalSignature, proof.digitalSignature, context);
        } else if (proposition.has_heightRange && proof.has_heightRange) {
            return Verifier.verifyHeightRange(proposition.heightRange, proof.heightRange, context);
        } else if (proposition.has_tickRange && proof.has_tickRange) {
            return Verifier.verifyTickRange(proposition.tickRange, proof.tickRange, context);
        } else if (proposition.has_lessThan && proof.has_lessThan) {
            return Verifier.verifyLessThan(proposition.lessThan, proof.lessThan, context);
        } else if (proposition.has_greaterThan && proof.has_greaterThan) {
            return Verifier.verifyGreaterThan(proposition.greaterThan, proof.greaterThan, context);
        } else if (proposition.has_equalTo && proof.has_equalTo) {
            return Verifier.verifyEqualTo(proposition.equalTo, proof.equalTo, context);
        } else if (proposition.has_threshold && proof.has_threshold) {
            return Verifier.verifyThreshold(proposition.threshold, proof.threshold, context);
        } else if (proposition.has_not && proof.has_not) {
            return Verifier.verifyNot(proposition.not, proof.not, context);
        } else if (proposition.has_and && proof.has_and) {
            return Verifier.verifyAnd(proposition.and, proof.and, context);
        } else if (proposition.has_or && proof.has_or) {
            return Verifier.verifyOr(proposition.or, proof.or, context);
        } else {
            return quivrEvaluationAuthorizationFailure(proof, proposition);
        }
    }

}

