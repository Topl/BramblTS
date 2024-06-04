import { Context } from '@/brambl/context.js';
import KeyPairSyntax from '@/brambl/syntax/key_pair_syntax.js';
import { CredentiallerInterpreter } from '@/brambl/wallet/credentialler_interpreter.js';
import { WalletApi } from '@/brambl/wallet/wallet_api.js';
import { isRight, none } from '@/common/functional/brambl_fp.js';
import { Proposer } from '@/quivr4s/quivr.js';
import {
  AssetMintingStatement,
  Attestation,
  Attestation_Predicate,
  Challenge,
  Datum_GroupPolicy,
  Datum_SeriesPolicy,
  Lock_Predicate,
  Proof,
} from 'topl_common';
import { describe, expect, test } from 'vitest';
import {
  dummyTxoAddress,
  mockChildKeyPair,
  mockDigest,
  mockDigestProposition,
  mockGroupPolicy,
  mockMainKeyPair,
  mockSeriesPolicy,
  mockSha256DigestProposition,
  quantity,
  txFull,
} from '../mock_helpers.js';
import { MockWalletKeyApi } from '../mock_wallet_key_api.js';
import { MockWalletStateApi } from '../mock_wallet_state_api.js';

describe('CredentiallerInterpreter', () => {
  const walletApi: WalletApi = new WalletApi(new MockWalletKeyApi());

  // test('prove: Single Input Transaction with Attestation.Image > Provable propositions have non-empty proofs', async () => {
  //   expect(true).toBe(true);
  // });

  test('prove: other fields on transaction are preserved', async () => {
    const testTx = txFull
      .withGroupPolicies([new Datum_GroupPolicy({ event: mockGroupPolicy })])
      .withSeriesPolicies([new Datum_SeriesPolicy({ event: mockSeriesPolicy })])
      .withMintingStatements([
        new AssetMintingStatement({
          groupTokenUtxo: dummyTxoAddress,
          seriesTokenUtxo: dummyTxoAddress,
          quantity: quantity,
        }),
      ]);

    const provenTx = await new CredentiallerInterpreter(
      walletApi,
      new MockWalletStateApi(),
      KeyPairSyntax.cryptoToPbKeyPair(mockMainKeyPair),
    ).prove(testTx);

    if (provenTx.inputs[0].attestation.value.case !== 'predicate')
      throw new Error('Invalid attestation, not a predicate');
    const provenPredicate = provenTx.inputs[0].attestation.value.value;
    const sameLen = provenPredicate.lock.challenges.length === provenPredicate.responses.length;
    const nonEmpty = provenPredicate.responses.every((proof) => {
      const x = proof.isEmpty();
      console.log(x);
      return !x;
    });
    expect(sameLen && nonEmpty && provenTx.signable().equals(testTx.signable())).toBe(true);
  });

  test('prove: Single Input Transaction with Attestation.Predicate > Provable propositions have non-empty proofs', async () => {
    const provenTx = await new CredentiallerInterpreter(
      walletApi,
      new MockWalletStateApi(),
      KeyPairSyntax.cryptoToPbKeyPair(mockMainKeyPair),
    ).prove(txFull);

    const provenPredicate = provenTx.inputs[0].attestation.value;
    if (provenPredicate.case !== 'predicate') throw new Error('Invalid attestation, not a predicate');
    const sameLen = provenPredicate.value.lock.challenges.length === provenPredicate.value.responses.length;
    const nonEmpty = provenPredicate.value.responses.every((proof) => {
      return !proof.isEmpty();
    });

    expect(sameLen && nonEmpty && provenTx.signable().equals(txFull.signable())).toBe(true);
  });

  test('prove: Single Input Transaction with Attestation.Predicate > Unprovable propositions have empty proofs', async () => {
    // Secrets are not available for the updated Signature and Digest propositions
    const testSignatureProposition = Proposer.signatureProposer(
      'invalid-routine',
      KeyPairSyntax.cryptoToPbKeyPair(mockChildKeyPair).vk,
    );
    const testDigestProposition = Proposer.digestProposer('invalid-routine', mockDigest);

    const testAttestation = new Attestation().withPredicate(
      new Attestation_Predicate({
        lock: new Lock_Predicate({
          challenges: [
            new Challenge().withRevealed(testSignatureProposition),
            new Challenge().withRevealed(testDigestProposition),
          ],
          threshold: 2,
        }),
        responses: [new Proof(), new Proof()],
      }),
    );

    const testTx = txFull.clone();
    testTx.inputs = txFull.inputs.map((stxo) => {
      const stxoCopy = stxo.clone();
      stxoCopy.attestation = testAttestation;
      return stxoCopy;
    });

    const provenTx = await new CredentiallerInterpreter(
      walletApi,
      new MockWalletStateApi(),
      KeyPairSyntax.cryptoToPbKeyPair(mockMainKeyPair),
    ).prove(testTx);

    const provenPredicate = provenTx.inputs[0].attestation.value;
    if (provenPredicate.case !== 'predicate') throw new Error('Invalid attestation, not a predicate');
    const sameLen = provenPredicate.value.lock.challenges.length === provenPredicate.value.responses.length;
    const correctLen = provenPredicate.value.lock.challenges.length === 2;
    const allEmpty = provenPredicate.value.responses.every((proof) => {
      return proof.isEmpty();
    });

    expect(sameLen && correctLen && allEmpty && provenTx.signable().equals(testTx.signable())).toBe(true);
  });

  // test('proveAndValidate: Single Input Transaction with Digest Propositions (Blake2b256 and Sha256)', async () => {
  //   const testAttestation = new Attestation().withPredicate(
  //     new Attestation_Predicate({
  //       lock: new Lock_Predicate({
  //         challenges: [
  //           new Challenge().withRevealed(mockDigestProposition), // Blake2b256
  //           new Challenge().withRevealed(mockSha256DigestProposition) // Sha256
  //         ],
  //         threshold: 2 // Both are required
  //       }),
  //       responses: [new Proof(), new Proof()]
  //     })
  //   );

  //   const testTx = txFull.clone();
  //   testTx.inputs = txFull.inputs.map(stxo => {
  //     const stxoCopy = stxo.clone();
  //     stxoCopy.attestation = testAttestation;
  //     return stxoCopy;
  //   });

  //   const ctx = new Context(testTx, 50, _ => none); // Tick and height are trivial

  //   // Secrets for the digests are available in the MockWalletStateApi
  //   const validateRes = await new CredentiallerInterpreter(
  //     walletApi,
  //     new MockWalletStateApi(),
  //     KeyPairSyntax.cryptoToPbKeyPair(mockMainKeyPair)
  //   ).proveAndValidate(testTx, ctx);

  //   const a = isRight(validateRes);

  //   // If successful, we know that we can prove and validate a transaction with Blake2b256 and Sha256 digest propositions
  //   console.log(a);
  //   // expect(a).toBe(true);
  //   console.log(a);
  // });
});
