// import { sizedEvidence } from '@/brambl/common/contains_evidence.js';
// import { ProtoConverters } from '@/brambl/utils/proto_converters.js';
// import { ExtendedEd25519, HardenedIndex, SoftIndex } from '@/crypto/crypto.js';
// import { Blake2b256 } from '@/crypto/hash/blake2B.js';
// import { Proposer, Prover } from '@/quivr4s/quivr.js';
// import {
//   Asset,
//   Attestation,
//   Attestation_Predicate,
//   Challenge,
//   Datum_IoTransaction,
//   Digest,
//   Event_IoTransaction,
//   FungibilityType,
//   Group,
//   Event_GroupPolicy as GroupPolicy,
//   Int128,
//   IoTransaction,
//   Lock,
//   Lock_Predicate,
//   LockAddress,
//   LockId,
//   Preimage,
//   Proof,
//   QuantityDescriptorType,
//   Schedule,
//   Series,
//   SeriesId,
//   Event_SeriesPolicy as SeriesPolicy,
//   SignableBytes,
//   SmallData,
//   SpentTransactionOutput,
//   Topl,
//   TransactionId,
//   TransactionOutputAddress,
//   UnspentTransactionOutput,
//   Value,
//   Witness
// } from 'topl_common';

import { sizedEvidence } from '@/brambl/common/contains_evidence.js';
import { ProtoConverters } from '@/brambl/utils/proto_converters.js';
import { blake2b256, ExtendedEd25519, HardenedIndex, sha256, SoftIndex } from '@/crypto/crypto.js';
import { Proposer, Prover } from '@/quivr4s/quivr.js';
import {
  Asset,
  Attestation,
  Attestation_Predicate,
  Challenge,
  Datum_IoTransaction,
  Digest,
  Event_IoTransaction,
  Group,
  Event_GroupPolicy as GroupPolicy,
  Indices,
  Int128,
  IoTransaction,
  Lock,
  Lock_Predicate,
  LockAddress,
  LockId,
  Preimage,
  Proof,
  Schedule,
  Series,
  SeriesId,
  Event_SeriesPolicy as SeriesPolicy,
  SignableBytes,
  SmallData,
  SpentTransactionOutput,
  Topl,
  TransactionId,
  TransactionOutputAddress,
  UnspentTransactionOutput,
  Value,
  Witness
} from 'topl_common';

export const fakeMsgBind = new SignableBytes({ value: new TextEncoder().encode('transaction binding') });

export const mockIndices = new Indices({ x: 0, y: 0, z: 0 });

// Hardcoding ExtendedEd25519
export const mockMainKeyPair = new ExtendedEd25519().deriveKeyPairFromSeed(new Uint8Array(96).fill(0));

export const mockChildKeyPair = new ExtendedEd25519().deriveKeyPairFromChildPath(mockMainKeyPair.signingKey, [
  new HardenedIndex(mockIndices.x),
  new SoftIndex(mockIndices.y),
  new SoftIndex(mockIndices.z)
]);

export const mockSigningRoutine = 'ExtendedEd25519';

export const mockSignatureProposition = Proposer.signatureProposer(
  mockSigningRoutine,
  ProtoConverters.keyPairToProto(mockChildKeyPair).vk
);

export const mockSignature = new Witness({
  value: new ExtendedEd25519().sign(mockChildKeyPair.signingKey, new Uint8Array(fakeMsgBind.value))
});

export const mockSignatureProof = Prover.signatureProver(mockSignature, fakeMsgBind);

export const mockPreimage = new Preimage({
  input: new TextEncoder().encode('secret'),
  salt: new TextEncoder().encode('salt')
});

export const mockDigestRoutine = 'Blake2b256';
export const mockSha256DigestRoutine = 'Sha256';

export const mockDigest = new Digest({
  value: blake2b256.hash(new Uint8Array([...mockPreimage.input, ...mockPreimage.salt]))
});

export const mockSha256Digest = new Digest({
  value: sha256.hash(new Uint8Array([...mockPreimage.input, ...mockPreimage.salt]))
});

export const mockSha256DigestProposition = Proposer.digestProposer(mockSha256DigestRoutine, mockSha256Digest);

export const mockDigestProposition = Proposer.digestProposer(mockDigestRoutine, mockDigest);
export const mockDigestProof = Prover.digestProver(mockPreimage, fakeMsgBind);

export const mockMin = BigInt(0);
export const mockMax = BigInt(100);
export const mockChain = 'header';
export const mockTickProposition = Proposer.tickProposer(mockMin, mockMax);
export const mockTickProof = Prover.tickProver(fakeMsgBind);

export const mockHeightProposition = Proposer.heightProposer(mockChain, mockMin, mockMax);
export const mockHeightProof = Prover.heightProver(fakeMsgBind);

export const mockLockedProposition = Proposer.lockedProposer(null);
export const mockLockedProof = Prover.lockedProver();

export const txDatum = new Datum_IoTransaction({
  event: new Event_IoTransaction({
    schedule: new Schedule({ min: BigInt(0), max: BigInt(Number.MAX_SAFE_INTEGER), timestamp: BigInt(Date.now()) }),
    metadata: new SmallData()
  })
});

// // Arbitrary Transaction that any new transaction can reference
export const dummyTx = new IoTransaction({ datum: txDatum });

export const dummyTxIdentifier = new TransactionId({ value: sizedEvidence(dummyTx).digest.value });

export const dummyTxoAddress = new TransactionOutputAddress({ network: 0, ledger: 0, index: 0, id: dummyTxIdentifier });

export const quantity = new Int128({ value: Uint8Array.of(1) });

export const lvlValue = new Value({ value: { case: 'lvl', value: { quantity: quantity } } });

export const trivialOutLock = new Lock({
  value: {
    case: 'predicate',
    value: new Lock_Predicate({
      challenges: [
        new Challenge({ proposition: { case: 'revealed', value: Proposer.tickProposer(BigInt(5), BigInt(15)) } })
      ],
      threshold: 1
    })
  }
});

export const trivialLockAddress = new LockAddress({
  network: 0,
  ledger: 0,
  id: new LockId({ value: sizedEvidence(trivialOutLock).digest.value })
});

export const inPredicateLockFull = new Lock_Predicate({
  challenges: [
    mockLockedProposition,
    mockDigestProposition,
    mockSignatureProposition,
    mockHeightProposition,
    mockTickProposition
  ].map(p => new Challenge({ proposition: { case: 'revealed', value: p } })),
  threshold: 3
});

// export const inLockFull = new Lock({
//   value: {
//     case: 'predicate',
//     value: inPredicateLockFull
//   }
// });

// export const inLockFullAddress = new LockAddress({
//   network: 0,
//   ledger: 0,
//   id: new LockId({ value: sizedEvidence(inLockFull).digest.value })
// });

export const inPredicateLockFullAttestation = new Attestation_Predicate({
  lock: inPredicateLockFull,
  responses: [mockLockedProof, mockDigestProof, mockSignatureProof, mockHeightProof, mockTickProof]
});

export const nonEmptyAttestation = new Attestation({
  value: {
    case: 'predicate',
    value: inPredicateLockFullAttestation
  }
});

export const output = new UnspentTransactionOutput({ address: trivialLockAddress, value: lvlValue });

// export const fullOutput = new UnspentTransactionOutput({ address: inLockFullAddress, value: lvlValue });

export const attFull = new Attestation({
  value: {
    case: 'predicate',
    value: new Attestation_Predicate({
      lock: inPredicateLockFull,
      responses: Array(inPredicateLockFull.challenges.length).fill(new Proof())
    })
  }
});

export const inputFull = new SpentTransactionOutput({
  address: dummyTxoAddress,
  attestation: attFull,
  value: lvlValue
});

export const txFull = new IoTransaction({ inputs: [inputFull], outputs: [output], datum: txDatum });

// export const mockVks = [
//   mockChildKeyPair.verificationKey,
//   new ExtendedEd25519().deriveKeyPairFromSeed(new Uint8Array(96).fill(1)).verificationKey
// ];

export const mockSeriesPolicy = new SeriesPolicy({
  label: 'Mock Series Policy',
  // tokenSupply: null,
  tokenSupply: 0,
  registrationUtxo: dummyTxoAddress
});

// export const mockSeriesPolicyImmutable = () => {
//   const mock = mockSeriesPolicy.clone();
//   mock.quantityDescriptor = QuantityDescriptorType.IMMUTABLE;
//   return mock;
// };
// export const mockSeriesPolicyFractionable = () => {
//   const mock = mockSeriesPolicy.clone();
//   mock.quantityDescriptor = QuantityDescriptorType.FRACTIONABLE;
//   return mock;
// };
// export const mockSeriesPolicyAccumulator = () => {
//   const mock = mockSeriesPolicy.clone();
//   mock.quantityDescriptor = QuantityDescriptorType.ACCUMULATOR;
//   return mock;
// };

export const mockGroupPolicy = new GroupPolicy({
  label: 'Mock Group Policy',
  registrationUtxo: dummyTxoAddress,
  fixedSeries: new SeriesId({ value: new Uint8Array() })
});

export const toplValue = new Value(
  new Value({ value: { case: 'topl', value: new Topl({ quantity: quantity, registration: null }) } })
);

export const seriesValue = new Value(
  new Value({
    value: {
      case: 'series',
      value: new Series({ seriesId: mockSeriesPolicy.computeId(), quantity: quantity, tokenSupply: 0 })
    }
  })
);

export const groupValue = new Value(
  new Value({
    value: { case: 'group', value: new Group({ groupId: mockGroupPolicy.computeId(), quantity: quantity }) }
  })
);

export const assetGroupSeries = new Value(
  new Value({
    value: {
      case: 'asset',
      value: new Asset({
        groupId: mockGroupPolicy.computeId(),
        seriesId: mockSeriesPolicy.computeId(),
        quantity: quantity
      })
    }
  })
);

// export const assetGroupSeriesImmutable = () => {
//   const a = assetGroupSeries.clone();
//   if (a.value.case !== 'asset') throw Error('Expected Asset');
//   a.value.value.quantityDescriptor = QuantityDescriptorType.IMMUTABLE;
//   a.value.value.seriesId = mockSeriesPolicyImmutable().computeId();
//   return a;
// };

// export const assetGroupSeriesFractionable = () => {
//   const a = assetGroupSeries.clone();
//   if (a.value.case !== 'asset') throw Error('Expected Asset');
//   a.value.value.quantityDescriptor = QuantityDescriptorType.FRACTIONABLE;
//   a.value.value.seriesId = mockSeriesPolicyFractionable().computeId();
//   return a;
// };

// export const assetGroupSeriesAccumulator = () => {
//   const a = assetGroupSeries.clone();
//   if (a.value.case !== 'asset') throw Error('Expected Asset');
//   a.value.value.quantityDescriptor = QuantityDescriptorType.ACCUMULATOR;
//   a.value.value.seriesId = mockSeriesPolicyAccumulator().computeId();
//   return a;
// };

// export const assetGroup = () => {
//   const a = assetGroupSeries.clone();
//   if (a.value.case !== 'asset') throw Error('Expected Asset');
//   a.value.value.fungibility = FungibilityType.GROUP;
//   a.value.value.seriesId = mockSeriesPolicyImmutable().computeId();
//   return a;
// };

// export const assetGroupImmutable = () => {
//   const a = assetGroup().clone();
//   if (a.value.case !== 'asset') throw Error('Expected Asset');
//   a.value.value.quantityDescriptor = QuantityDescriptorType.IMMUTABLE;
//   const b = mockSeriesPolicyImmutable().clone();
//   b.fungibility = FungibilityType.GROUP;
//   a.value.value.seriesId = b.computeId();
//   return a;
// };

// export const assetGroupFractionable = () => {
//   const a = assetGroup().clone();
//   if (a.value.case !== 'asset') throw Error('Expected Asset');
//   a.value.value.quantityDescriptor = QuantityDescriptorType.FRACTIONABLE;
//   const b = mockSeriesPolicyImmutable().clone();
//   b.fungibility = FungibilityType.GROUP;
//   a.value.value.seriesId = b.computeId();
//   return a;
// };

// export const assetGroupAccumulator = () => {
//   const a = assetGroup().clone();
//   if (a.value.case !== 'asset') throw Error('Expected Asset');
//   a.value.value.quantityDescriptor = QuantityDescriptorType.ACCUMULATOR;
//   const b = mockSeriesPolicyImmutable().clone();
//   b.fungibility = FungibilityType.GROUP;
//   a.value.value.seriesId = b.computeId();
//   a.value.value = b;
//   return a;
// };

// export const assetSeries = () => {
//   const a = assetGroupSeries.clone();
//   if (a.value.case !== 'asset') throw Error('Expected Asset');
//   const b = a.value.value.clone();
//   b.fungibility = FungibilityType.SERIES;
//   const c = mockSeriesPolicy.clone();
//   c.fungibility = FungibilityType.SERIES;
//   b.seriesId = c.computeId();
//   a.value.value = b;
//   return a;
// };

// export const assetSeriesImmutable = () => {
//   const a = assetSeries().clone();
//   if (a.value.case !== 'asset') throw Error('Expected Asset');
//   const b = a.value.value.clone();
//   b.quantityDescriptor = QuantityDescriptorType.IMMUTABLE;
//   const c = mockSeriesPolicyImmutable().clone();
//   c.fungibility = FungibilityType.SERIES;
//   b.seriesId = c.computeId();
//   return (a.value.value = b);
// };

// export const assetSeriesFractionable = () => {
//   const a = assetSeries().clone();
//   if (a.value.case !== 'asset') throw Error('Expected Asset');
//   const b = a.value.value.clone();
//   b.quantityDescriptor = QuantityDescriptorType.FRACTIONABLE;
//   const c = mockSeriesPolicyFractionable().clone();
//   c.fungibility = FungibilityType.SERIES;
//   b.seriesId = c.computeId();
//   return (a.value.value = b);
// };

// export const assetSeriesAccumulator = () => {
//   const a = assetSeries().clone();
//   if (a.value.case !== 'asset') throw Error('Expected Asset');
//   const b = a.value.value.clone();
//   b.quantityDescriptor = QuantityDescriptorType.ACCUMULATOR;
//   const c = mockSeriesPolicyAccumulator().clone();
//   c.fungibility = FungibilityType.SERIES;
//   b.seriesId = c.computeId();
//   return (a.value.value = b);
// };
