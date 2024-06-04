import { either, option } from 'fp-ts';
import {
  DigestVerification,
  Message,
  Proof,
  Proof_And,
  Proof_Digest,
  Proof_DigitalSignature,
  Proof_EqualTo,
  Proof_ExactMatch,
  Proof_GreaterThan,
  Proof_HeightRange,
  Proof_LessThan,
  Proof_Not,
  Proof_Or,
  Proof_Threshold,
  Proof_TickRange,
  Proposition,
  Proposition_And,
  Proposition_Digest,
  Proposition_DigitalSignature,
  Proposition_EqualTo,
  Proposition_ExactMatch,
  Proposition_GreaterThan,
  Proposition_HeightRange,
  Proposition_LessThan,
  Proposition_Not,
  Proposition_Or,
  Proposition_Threshold,
  Proposition_TickRange,
  SignatureVerification,
  TxBind
} from 'topl_common';
import { type QuivrResult, quivrEvaluationAuthorizationFailure } from '../common/quivr_result.js';

import { Tokens } from '../../tokens.js';
import { arraysEqual } from '../../utils/list_utils.js';
import type DynamicContext from '../runtime/dynamic_context.js';
import { ValidationError } from '../runtime/quivr_runtime_error.js';
import { blake2b256 } from '@/crypto/crypto.js';

export class Verifier {
  /// Will return [QuivrResult] Left => [QuivrRuntimeError.messageAuthorizationFailure] if the proof is invalid.
  static _evaluateBlake2b256Bind (
    tag: string,
    proof: Proof,
    proofTxBind: TxBind,
    context: DynamicContext<string>
  ): QuivrResult<boolean> {
    const sb = context.signableBytes;
    const merge = new Uint8Array([...Buffer.from(tag, 'utf8'), ...sb.value]);
    const verifierTxBind = blake2b256.hash(merge);

    const result = arraysEqual(verifierTxBind, proofTxBind.value);

    return result
      ? either.right(result)
      : either.left(
          ValidationError.messageAuthorizationFailure({
            name: 'Blake2b256Bind',
            message: `Error in evaluating Blake2b256Bind : ${proof.toJsonString()}`
          })
        );
  }

  static evaluateResult (
    messageResult: QuivrResult<boolean>,
    evalResult: QuivrResult<unknown>,
    {
      proposition,
      proof
    }: {
      proposition: Proposition;
      proof: Proof;
    }
  ): QuivrResult<boolean> {
    if (either.isRight(messageResult) && either.isRight(evalResult)) {
      return either.right(true);
    } else {
      return quivrEvaluationAuthorizationFailure(proof, proposition);
    }
  }

  static verifyLocked (): QuivrResult<boolean> {
    return either.left(
      ValidationError.lockedPropositionIsUnsatisfiable({
        name: 'Locked',
        message: 'Locked proposition is unsatisfiable'
      })
    );
  }

  static verifyDigest (
    proposition: Proposition_Digest,
    proof: Proof_Digest,
    context: DynamicContext<string>
  ): QuivrResult<boolean> {
    const wrappedProposition: Proposition = new Proposition({
      value: { case: 'digest', value: proposition }
    });
    const wrappedProof: Proof = new Proof({
      value: { case: 'digest', value: proof }
    });

    const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.digest, wrappedProof, proof.transactionBind, context);

    either.flatMap;

    if (either.isLeft(messageResult)) return messageResult;

    const evalResult = context.digestVerify(
      proposition.routine,
      new DigestVerification({ digest: proposition.digest, preimage: proof.preimage })
    );

    return Verifier.evaluateResult(messageResult, evalResult, {
      proposition: wrappedProposition,
      proof: wrappedProof
    });
  }

  static verifySignature (
    proposition: Proposition_DigitalSignature,
    proof: Proof_DigitalSignature,
    context: DynamicContext<string>
  ): QuivrResult<boolean> {
    const wrappedProposition: Proposition = new Proposition({
      value: { case: 'digitalSignature', value: proposition }
    });
    const wrappedProof: Proof = new Proof({
      value: { case: 'digitalSignature', value: proof }
    });

    const messageResult = Verifier._evaluateBlake2b256Bind(
      Tokens.digitalSignature,
      wrappedProof,
      proof.transactionBind,
      context
    );

    if (either.isLeft(messageResult)) return messageResult;

    const signedMessage = context.signableBytes;
    const verification = new SignatureVerification({
      verificationKey: proposition.verificationKey,
      signature: proof.witness,
      message: new Message({ value: signedMessage.value })
    });

    const evalResult = context.signatureVerify(proposition.routine, verification);

    return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
  }

  static verifyHeightRange (
    proposition: Proposition_HeightRange,
    proof: Proof_HeightRange,
    context: DynamicContext<string>
  ): QuivrResult<boolean> {
    const wrappedProposition: Proposition = new Proposition({ value: { case: 'heightRange', value: proposition } });

    const wrappedProof: Proof = new Proof({
      value: { case: 'heightRange', value: proof }
    });

    const messageResult = Verifier._evaluateBlake2b256Bind(
      Tokens.heightRange,
      wrappedProof,
      proof.transactionBind,
      context
    );

    if (either.isLeft(messageResult)) return messageResult;

    const x = context.heightOf(proposition.chain);
    const chainHeight = option.fold(
      () => quivrEvaluationAuthorizationFailure<bigint>(proof, proposition),
      (value: bigint) => either.right(value)
    )(x);

    if (either.isLeft(chainHeight)) return either.left(chainHeight.left);

    const height = chainHeight.right!;

    const evalResult: QuivrResult<boolean> =
      proposition.max >= height && proposition.min <= height
        ? either.right(true)
        : quivrEvaluationAuthorizationFailure(proof, proposition);

    return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
  }

  static verifyTickRange (
    proposition: Proposition_TickRange,
    proof: Proof_TickRange,
    context: DynamicContext<string>
  ): QuivrResult<boolean> {
    const wrappedProposition: Proposition = new Proposition({ value: { case: 'tickRange', value: proposition } });

    const wrappedProof: Proof = new Proof({
      value: { case: 'tickRange', value: proof }
    });

    const messageResult = Verifier._evaluateBlake2b256Bind(
      Tokens.tickRange,
      wrappedProof,
      proof.transactionBind,
      context
    );

    if (either.isLeft(messageResult)) return messageResult;

    if (context.currentTick < proposition.min || context.currentTick > proposition.max) {
      return quivrEvaluationAuthorizationFailure(proof, proposition);
    }
    const tick = context.currentTick;

    const evalResult: QuivrResult<boolean> =
      proposition.min <= tick && tick <= proposition.max
        ? either.right(true)
        : quivrEvaluationAuthorizationFailure(proof, proposition);

    return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
  }

  static verifyExactMatch (
    proposition: Proposition_ExactMatch,
    proof: Proof_ExactMatch,
    context: DynamicContext<string>
  ): QuivrResult<boolean> {
    const wrappedProposition: Proposition = new Proposition({ value: { case: 'exactMatch', value: proposition } });

    const wrappedProof: Proof = new Proof({
      value: { case: 'exactMatch', value: proof }
    });

    const messageResult = Verifier._evaluateBlake2b256Bind(
      Tokens.exactMatch,
      wrappedProof,
      proof.transactionBind,
      context
    );

    if (either.isLeft(messageResult)) return messageResult;

    const evalResult: QuivrResult<boolean> = context.exactMatch(proposition.location, proposition.compareTo)
      ? either.right(true)
      : quivrEvaluationAuthorizationFailure(proof, proposition);

    return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
  }

  static verifyLessThan (
    proposition: Proposition_LessThan,
    proof: Proof_LessThan,
    context: DynamicContext<string>
  ): QuivrResult<boolean> {
    const wrappedProposition: Proposition = new Proposition({ value: { case: 'lessThan', value: proposition } });

    const wrappedProof: Proof = new Proof({
      value: { case: 'lessThan', value: proof }
    });

    const messageResult = Verifier._evaluateBlake2b256Bind(
      Tokens.lessThan,
      wrappedProof,
      proof.transactionBind,
      context
    );

    if (either.isLeft(messageResult)) return messageResult;

    const evalResult: QuivrResult<boolean> = context.lessThan(proposition.location, proposition.compareTo.value)
      ? either.right(true)
      : quivrEvaluationAuthorizationFailure(proof, proposition);

    return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
  }

  static verifyGreaterThan (
    proposition: Proposition_GreaterThan,
    proof: Proof_GreaterThan,
    context: DynamicContext<string>
  ): QuivrResult<boolean> {
    const wrappedProposition: Proposition = new Proposition({ value: { case: 'greaterThan', value: proposition } });

    const wrappedProof: Proof = new Proof({
      value: { case: 'greaterThan', value: proof }
    });

    const messageResult = Verifier._evaluateBlake2b256Bind(
      Tokens.greaterThan,
      wrappedProof,
      proof.transactionBind,
      context
    );

    if (either.isLeft(messageResult)) return messageResult;

    const evalResult: QuivrResult<boolean> = context.greaterThan(proposition.location, proposition.compareTo.value)
      ? either.right(true)
      : quivrEvaluationAuthorizationFailure(proof, proposition);

    return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
  }

  static verifyEqualTo (
    proposition: Proposition_EqualTo,
    proof: Proof_EqualTo,
    context: DynamicContext<string>
  ): QuivrResult<boolean> {
    const wrappedProposition: Proposition = new Proposition({ value: { case: 'equalTo', value: proposition } });

    const wrappedProof: Proof = new Proof({
      value: { case: 'equalTo', value: proof }
    });

    const messageResult = Verifier._evaluateBlake2b256Bind(
      Tokens.equalTo,
      wrappedProof,
      proof.transactionBind,
      context
    );

    if (either.isLeft(messageResult)) return messageResult;

    const evalResult: QuivrResult<boolean> = context.equalTo(proposition.location, proposition.compareTo.value)
      ? either.right(true)
      : quivrEvaluationAuthorizationFailure(proof, proposition);

    return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
  }

  static verifyThreshold (
    proposition: Proposition_Threshold,
    proof: Proof_Threshold,
    context: DynamicContext<string>
  ): QuivrResult<boolean> {
    const wrappedProposition: Proposition = new Proposition({ value: { case: 'threshold', value: proposition } });

    const wrappedProof: Proof = new Proof({
      value: { case: 'threshold', value: proof }
    });

    const messageResult = Verifier._evaluateBlake2b256Bind(
      Tokens.threshold,
      wrappedProof,
      proof.transactionBind,
      context
    );

    if (either.isLeft(messageResult)) return either.left(messageResult.left);

    // Initialize as true;
    let evalResult: QuivrResult<boolean> = either.right(false);

    if (proposition.threshold == 0) {
      evalResult = either.right(true);
    } else if (
      proposition.threshold > proposition.challenges.length ||
      proof.responses.length === 0 ||
      proof.responses.length != proposition.challenges.length
    ) {
      evalResult = quivrEvaluationAuthorizationFailure(proof, proposition);
    } else {
      let successCount: number = 0;
      for (let i = 0; i < proposition.challenges.length && successCount < proposition.threshold; i++) {
        const challenge = proposition.challenges[i];
        const response = proof.responses[i];
        const verifyResult = Verifier.verify(challenge, response, context);
        if (either.isRight(verifyResult)) {
          successCount++;
        }
      }
      if (successCount < proposition.threshold) {
        evalResult = quivrEvaluationAuthorizationFailure(proof, proposition);
      }
    }

    return Verifier.evaluateResult(messageResult, evalResult, { proposition: wrappedProposition, proof: wrappedProof });
  }

  static verifyNot (
    proposition: Proposition_Not,
    proof: Proof_Not,
    context: DynamicContext<string>
  ): QuivrResult<boolean> {
    const wrappedProposition: Proposition = new Proposition({ value: { case: 'not', value: proposition } });

    const wrappedProof: Proof = new Proof({
      value: { case: 'not', value: proof }
    });

    const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.not, wrappedProof, proof.transactionBind, context);
    if (either.isLeft(messageResult)) return either.left(messageResult.left);

    const evalResult = Verifier.verify(proposition.proposition, proof.proof, context);

    const beforeReturn: QuivrResult<boolean> = Verifier.evaluateResult(messageResult, evalResult, {
      proposition: wrappedProposition,
      proof: wrappedProof
    });

    return either.isRight(beforeReturn) ? quivrEvaluationAuthorizationFailure(proof, proposition) : either.right(true);
  }

  static verifyAnd (
    proposition: Proposition_And,
    proof: Proof_And,
    context: DynamicContext<string>
  ): QuivrResult<boolean> {
    const wrappedProposition: Proposition = new Proposition({ value: { case: 'and', value: proposition } });

    const wrappedProof: Proof = new Proof({
      value: { case: 'and', value: proof }
    });

    const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.and, wrappedProof, proof.transactionBind, context);
    if (either.isLeft(messageResult)) return either.left(messageResult.left);

    const leftResult = Verifier.verify(proposition.left, proof.left, context);
    if (either.isLeft(leftResult)) return leftResult;

    const rightResult = Verifier.verify(proposition.right, proof.right, context);
    if (either.isRight(rightResult)) return rightResult;

    // We're not checking the value of right as it's existence is enough to satisfy this condition
    if (either.isRight(leftResult) && either.isRight(rightResult)) return either.right(true);

    return quivrEvaluationAuthorizationFailure(wrappedProposition, wrappedProof);
  }

  static verifyOr (proposition: Proposition_Or, proof: Proof_Or, context: DynamicContext<string>): QuivrResult<boolean> {
    // const wrappedProposition: Proposition = new Proposition({value: { case: 'or', value: proposition}});

    const wrappedProof: Proof = new Proof({
      value: { case: 'or', value: proof }
    });

    const messageResult = Verifier._evaluateBlake2b256Bind(Tokens.or, wrappedProof, proof.transactionBind, context);
    if (either.isLeft(messageResult)) return either.left(messageResult.left);

    const leftResult = Verifier.verify(proposition.left, proof.left, context);
    if (either.isRight(leftResult)) either.right(true);

    const rightResult = Verifier.verify(proposition.right, proof.right, context);
    return rightResult;
  }

  static verify (proposition: Proposition, proof: Proof, context: DynamicContext<string>): QuivrResult<boolean> {
    // note: good candidate for patternmatching, but can't figure out how protobuf-es handles the type matching in that case
    if (proposition.value.case === 'locked' && proof.value.case === 'locked') {
      return Verifier.verifyLocked();
    } else if (proposition.value.case === 'digest' && proof.value.case === 'digest') {
      return Verifier.verifyDigest(proposition.value.value, proof.value.value, context);
    } else if (proposition.value.case === 'digitalSignature' && proof.value.case === 'digitalSignature') {
      return Verifier.verifySignature(proposition.value.value, proof.value.value, context);
    } else if (proposition.value.case === 'heightRange' && proof.value.case === 'heightRange') {
      return Verifier.verifyHeightRange(proposition.value.value, proof.value.value, context);
    } else if (proposition.value.case === 'tickRange' && proof.value.case === 'tickRange') {
      return Verifier.verifyTickRange(proposition.value.value, proof.value.value, context);
    } else if (proposition.value.case === 'lessThan' && proof.value.case === 'lessThan') {
      return Verifier.verifyLessThan(proposition.value.value, proof.value.value, context);
    } else if (proposition.value.case === 'greaterThan' && proof.value.case === 'greaterThan') {
      return Verifier.verifyGreaterThan(proposition.value.value, proof.value.value, context);
    } else if (proposition.value.case === 'equalTo' && proof.value.case === 'equalTo') {
      return Verifier.verifyEqualTo(proposition.value.value, proof.value.value, context);
    } else if (proposition.value.case === 'threshold' && proof.value.case === 'threshold') {
      return Verifier.verifyThreshold(proposition.value.value, proof.value.value, context);
    } else if (proposition.value.case === 'not' && proof.value.case === 'not') {
      return Verifier.verifyNot(proposition.value.value, proof.value.value, context);
    } else if (proposition.value.case === 'and' && proof.value.case === 'and') {
      return Verifier.verifyAnd(proposition.value.value, proof.value.value, context);
    } else if (proposition.value.case === 'or' && proof.value.case === 'or') {
      return Verifier.verifyOr(proposition.value.value, proof.value.value, context);
    } else {
      return quivrEvaluationAuthorizationFailure(proof, proposition);
    }
  }
}
