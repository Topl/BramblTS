import { ByteString } from '@/common/types/byte_string.js';
import { Tokens } from '@/quivr4s/tokens.js';
import { bigIntToUint8Array } from '@/utils/extensions.js';
import { getOrElse, type Option } from 'fp-ts/lib/Option.js';
import {
  AccumulatorRootId,
  Asset,
  Attestation,
  Attestation_Commitment,
  Attestation_Image,
  Attestation_Predicate,
  Box,
  Challenge,
  Challenge_PreviousProposition,
  Datum,
  Datum_Eon,
  Datum_Epoch,
  Datum_Era,
  Datum_GroupPolicy,
  Datum_Header,
  Datum_IoTransaction,
  Datum_SeriesPolicy,
  Digest,
  Duration,
  Ed25519Vk,
  Event,
  Event_Eon,
  Event_Epoch,
  Event_Era,
  Event_GroupPolicy,
  Event_Header,
  Event_IoTransaction,
  Event_SeriesPolicy,
  Evidence,
  ExtendedEd25519Vk,
  type FungibilityType,
  Group,
  GroupId,
  ImmutableBytes,
  Int128,
  IoTransaction,
  Lock,
  Lock_Commitment,
  Lock_Image,
  Lock_Predicate,
  LockAddress,
  LockId,
  Lvl,
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
  Proposition,
  Proposition_And,
  Proposition_Digest,
  Proposition_DigitalSignature,
  Proposition_EqualTo,
  Proposition_ExactMatch,
  Proposition_GreaterThan,
  Proposition_HeightRange,
  Proposition_LessThan,
  Proposition_Locked,
  Proposition_Not,
  Proposition_Or,
  Proposition_Threshold,
  Proposition_TickRange,
  type QuantityDescriptorType,
  Ratio,
  Root,
  Schedule,
  Series,
  SeriesId,
  SignatureKesProduct,
  SignatureKesSum,
  SmallData,
  SpentTransactionOutput,
  StakingAddress,
  StakingRegistration,
  Struct,
  Topl,
  TransactionId,
  TransactionInputAddress,
  TransactionOutputAddress,
  TxBind,
  UnspentTransactionOutput,
  UpdateProposal,
  Value,
  VerificationKey,
  Witness
} from 'topl_common';
import { isFungibilityType, isOptionContainsImmutable, isQuantityDescriptorType } from '../utils/guard.js';
import { Identifier } from './tags.js';

/**
 * provides factory methods for creating [ContainsImmutable] objects
 */
export class ContainsImmutable {
  readonly immutableBytes: ImmutableBytes;

  constructor (immutableBytes: ImmutableBytes) {
    this.immutableBytes = immutableBytes;
  }

  ///factories follow

  static empty (): ContainsImmutable {
    /// base function, lets not use extension methods here to prevent cyclic dependencies
    return new ContainsImmutable(new ImmutableBytes());
  }

  /**
   * Creates a new `ContainsImmutable` instance from a `Uint8Array`.
   *
   * @param uInt8Array - The `Uint8Array` to create the `ContainsImmutable` instance from.
   * @returns A new `ContainsImmutable` instance.
   */
  static uInt8Array (uInt8Array: Uint8Array): ContainsImmutable {
    /// base function, lets not use extension methods here to prevent cyclic dependencies
    return new ContainsImmutable(_Uint8ArrayToImmutableBytes(uInt8Array));
  }

  static number (i: number): ContainsImmutable {
    if (typeof i === 'undefined')  throw Error("Number passed is undefined")
    const x = i ?? 0;
    const immutableBytes = new ImmutableBytes({ value: x.bToUint8Array() });
    return immutableBytes.immutable();
  }

  static string (str: string): ContainsImmutable {
    const encoder = new TextEncoder();
    const uint8Array = encoder.encode(str);
    const immutableBytes = new ImmutableBytes({ value: uint8Array });
    return immutableBytes.immutable();
  }

  static byteString (byteString: ByteString): ContainsImmutable {
    const immutableBytes = new ImmutableBytes({ value: byteString.value });
    return immutableBytes.immutable();
  }

  static bigInt (i: bigint | BigInt): ContainsImmutable {
    const value = i instanceof BigInt ? i.valueOf() : i;
    const x = bigIntToUint8Array(value);
    return x.bImmutable();
  }

  static int128 (i: Int128): ContainsImmutable {
    return i.value.bImmutable();
  }

  static option (i: Option<ContainsImmutable>): ContainsImmutable {
    return getOrElse(() => this.empty())(i);
  }

  static smallData (i: SmallData): ContainsImmutable {
    return i.value.bImmutable();
  }

  static root (i: Root): ContainsImmutable {
    return i.value.bImmutable();
  }

  static struct (i: Struct): ContainsImmutable {
    // not sure if this is the correct way to handle this
    return i.fields.values.toBinary().bImmutable();
  }

  /**
   * Converts a VerificationKey object to a ContainsImmutable object.
   * @param vk - The VerificationKey object to convert.
   * @returns The corresponding ContainsImmutable object.
   * @throws Error if the verification key is invalid.
   */
  static verificationKey (vk: VerificationKey): ContainsImmutable {
    switch (vk.vk.case) {
      case 'ed25519':
        return this.ed25519VerificationKey(vk.vk.value);
      case 'extendedEd25519':
        return this.extendedEd25519VerificationKey(vk.vk.value);
      default:
        throw Error('Invalid verification key');
    }
  }

  static ed25519VerificationKey (vk: Ed25519Vk): ContainsImmutable {
    return vk.value.bImmutable();
  }

  static extendedEd25519VerificationKey (vk: ExtendedEd25519Vk): ContainsImmutable {
    return vk.vk.value.bImmutable().add(vk.chainCode.bImmutable());
  }

  static witness (w: Witness): ContainsImmutable {
    return w.value.bImmutable();
  }

  static datum (d: Datum): ContainsImmutable {
    switch (d.value.case) {
      case 'eon':
        return this.eonDatum(d.value.value);
      case 'era':
        return this.eraDatum(d.value.value);
      case 'epoch':
        return this.epochDatum(d.value.value);
      case 'header':
        return this.headerDatum(d.value.value);
      case 'ioTransaction':
        return this.ioTransactionDatum(d.value.value);
      case 'groupPolicy':
        return this.groupPolicyDatum(d.value.value);
      case 'seriesPolicy':
        return this.seriesPolicyDatum(d.value.value);
      default:
        throw new Error('Invalid datum value');
    }
  }

  static eonDatum (eon: Datum_Eon): ContainsImmutable {
    return this.eonEvent(eon.event);
  }

  static eraDatum (era: Datum_Era): ContainsImmutable {
    return this.eraEvent(era.event);
  }

  static epochDatum (epoch: Datum_Epoch): ContainsImmutable {
    return this.epochEvent(epoch.event);
  }

  static headerDatum (header: Datum_Header): ContainsImmutable {
    return this.headerEvent(header.event);
  }

  static ioTransactionDatum (ioTransaction: Datum_IoTransaction): ContainsImmutable {
    return this.iotxEventImmutable(ioTransaction.event);
  }

  static groupPolicyDatum (groupPolicy: Datum_GroupPolicy): ContainsImmutable {
    return this.groupPolicyEvent(groupPolicy.event);
  }

  static seriesPolicyDatum (seriesPolicy: Datum_SeriesPolicy): ContainsImmutable {
    return this.seriesPolicyEvent(seriesPolicy.event);
  }

  static ioTransaction (iotx: IoTransaction): ContainsImmutable {
    return this.list(iotx.inputs)
      .add(this.list(iotx.outputs))
      .add(this.ioTransactionDatum(iotx.datum))
      .add(this.list(iotx.groupPolicies))
      .add(this.list(iotx.seriesPolicies));
  }

  static x (iotx: IoTransaction): ContainsImmutable {
    return this.list(iotx.inputs)
      .add(this.list(iotx.outputs))
      .add(this.ioTransactionDatum(iotx.datum))
      .add(this.list(iotx.groupPolicies))
      .add(this.list(iotx.seriesPolicies));
  }

  static iotxSchedule (schedule: Schedule): ContainsImmutable {
    return this.bigInt(schedule.min).add(this.bigInt(schedule.max));
  }

  static spentOutput (stxo: SpentTransactionOutput): ContainsImmutable {
    return this.transactionOutputAddress(stxo.address)
      .add(this.attestation(stxo.attestation))
      .add(this.value(stxo.value));
  }

  static unspentOutput (utxo: UnspentTransactionOutput): ContainsImmutable {
    return this.lockAddress(utxo.address).add(this.value(utxo.value));
  }

  static box (box: Box): ContainsImmutable {
    return this.lock(box.lock).add(this.value(box.value));
  }

  static value (v: Value): ContainsImmutable {
    switch (v.value.case) {
      case 'lvl':
        return this.lvlValue(v.value.value);
      case 'topl':
        return this.toplValue(v.value.value);
      case 'asset':
        return this.assetValue(v.value.value);
      case 'series':
        return this.seriesValue(v.value.value);
      case 'group':
        return this.groupValue(v.value.value);
      case 'updateProposal':
        return this.updateProposal(v.value.value);
      default:
        return [0].bImmutable();
    }
  }

  static lvlValue (v: Lvl): ContainsImmutable {
    return this.int128(v.quantity);
  }

  static toplValue (v: Topl): ContainsImmutable {
    return this.int128(v.quantity).add(this.stakingRegistration(v.registration));
  }

  static assetValue (asset: Asset): ContainsImmutable {
    return this.groupIdentifier(asset.groupId)
      .add(this.seriesIdValue(asset.seriesId))
      .add(this.int128(asset.quantity))
      .add(asset.groupAlloy.bImmutable())
      .add(asset.seriesAlloy.bImmutable())
      .add(this.fungibility(asset.fungibility))
      .add(this.quantityDescriptor(asset.quantityDescriptor))
      .add(this.struct(asset.ephemeralMetadata))
      .add(asset.commitment.bImmutable());
  }

  static seriesValue (s: Series): ContainsImmutable {
    return this.seriesIdValue(s.seriesId)
      .add(this.int128(s.quantity))
      .add(s.tokenSupply.bImmutable())
      .add(this.quantityDescriptor(s.quantityDescriptor))
      .add(this.fungibility(s.fungibility));
  }

  static groupValue (g: Group): ContainsImmutable {
    return this.groupIdentifier(g.groupId).add(this.int128(g.quantity)).add(this.seriesIdValue(g.fixedSeries));
  }

  static ratio (r: Ratio): ContainsImmutable {
    return this.int128(r.numerator).add(this.int128(r.denominator));
  }

  //TODO: get google protos
  static duration (d: Duration): ContainsImmutable {
    return this.bigInt(d.seconds).add(d.nanos.bImmutable());
  }

  static updateProposal (up: UpdateProposal): ContainsImmutable {
    return this.string(up.label)
      .add(this.ratio(up.fEffective))
      .add(up.vrfLddCutoff.bImmutable())
      .add(up.vrfPrecision.bImmutable())
      .add(this.ratio(up.vrfBaselineDifficulty))
      .add(this.ratio(up.vrfAmplitude))
      .add(this.bigInt(up.chainSelectionKLookback))
      .add(this.duration(up.slotDuration))
      .add(this.bigInt(up.forwardBiasedSlotWindow))
      .add(this.bigInt(up.operationalPeriodsPerEpoch))
      .add(up.kesKeyHours.bImmutable())
      .add(up.kesKeyMinutes.bImmutable());
  }

  static fungibility (f: FungibilityType): ContainsImmutable {
    return f.bImmutable();
  }

  static quantityDescriptor (qdt: QuantityDescriptorType): ContainsImmutable {
    return qdt.bImmutable();
  }

  static stakingAddress (v: StakingAddress): ContainsImmutable {
    return v.value.bImmutable();
  }

  static evidence (e: Evidence): ContainsImmutable {
    return this.digest(e.digest);
  }

  static digest (d: Digest): ContainsImmutable {
    return d.value.bImmutable();
  }

  static preimage (pre: Preimage): ContainsImmutable {
    return pre.input.bImmutable().add(pre.salt.bImmutable());
  }

  static accumulatorRoot32Identifier (id: AccumulatorRootId): ContainsImmutable {
    return this.string(Identifier.accumulatorRoot32).add(id.value.bImmutable());
  }

  static boxLock32Identifier (id: LockId): ContainsImmutable {
    return this.string(Identifier.lock32).add(id.value.bImmutable());
  }

  static transactionIdentifier (id: TransactionId): ContainsImmutable {
    return this.string(Identifier.ioTransaction32).add(id.value.bImmutable());
  }

  static groupIdentifier (id: GroupId): ContainsImmutable {
    return this.string(Identifier.group32).add(id.value.bImmutable());
  }

  static seriesIdValue (sid: SeriesId): ContainsImmutable {
    return this.string(Identifier.series32).add(sid.value.bImmutable());
  }

  static transactionOutputAddress (v: TransactionOutputAddress): ContainsImmutable {
    return v.network
      .bImmutable()
      .add(v.ledger.bImmutable())
      .add(v.index.bImmutable())
      .add(this.transactionIdentifier(v.id));
  }

  static lockAddress (v: LockAddress): ContainsImmutable {
    return v.network.bImmutable().add(v.ledger.bImmutable()).add(this.boxLock32Identifier(v.id));
  }

  static signatureKesSum (v: SignatureKesSum): ContainsImmutable {
    return v.verificationKey.bImmutable().add(v.signature.bImmutable()).add(this.list(v.witness));
  }

  static signatureKesProduct (v: SignatureKesProduct): ContainsImmutable {
    return this.signatureKesSum(v.superSignature).add(this.signatureKesSum(v.subSignature)).add(v.subRoot.bImmutable());
  }

  static stakingRegistration (v: StakingRegistration): ContainsImmutable {
    return this.signatureKesProduct(v.signature).add(this.stakingAddress(v.address));
  }

  static predicateLock (predicate: Lock_Predicate): ContainsImmutable {
    return predicate.threshold.bImmutable().add(this.list(predicate.challenges));
  }

  static imageLock (image: Lock_Image): ContainsImmutable {
    return image.threshold.bImmutable().add(this.list(image.leaves));
  }

  static commitmentLock (commitment: Lock_Commitment): ContainsImmutable {
    return commitment.threshold
      .bImmutable()
      .add(commitment.root.value.length.bImmutable())
      .add(this.accumulatorRoot32Identifier(commitment.root));
  }

  static lock (lock: Lock): ContainsImmutable {
    switch (lock.value.case) {
      case 'predicate':
        return this.predicateLock(lock.value.value);
      case 'image':
        return this.imageLock(lock.value.value);
      case 'commitment':
        return this.commitmentLock(lock.value.value);
      default:
        throw new Error(`Invalid Lock type: discriminated union returned never!`);
    }
  }

  static predicateAttestation (attestation: Attestation_Predicate): ContainsImmutable {
    return this.predicateLock(attestation.lock).add(this.list(attestation.responses));
  }

  static imageAttestation (attestation: Attestation_Image): ContainsImmutable {
    return this.imageLock(attestation.lock).add(this.list(attestation.known)).add(this.list(attestation.responses));
  }

  static commitmentAttestation (attestation: Attestation_Commitment): ContainsImmutable {
    return this.commitmentLock(attestation.lock)
      .add(this.list(attestation.known))
      .add(this.list(attestation.responses));
  }

  static attestation (attestation: Attestation): ContainsImmutable {
    switch (attestation.value.case) {
      case 'predicate':
        return this.predicateAttestation(attestation.value.value);
      case 'image':
        return this.imageAttestation(attestation.value.value);
      case 'commitment':
        return this.commitmentAttestation(attestation.value.value);
      default:
        return this.empty();
    }
  }

  static transactionInputAddressContains (address: TransactionInputAddress): ContainsImmutable {
    return address.network
      .bImmutable()
      .add(address.ledger.bImmutable())
      .add(address.index.bImmutable())
      .add(this.transactionIdentifier(address.id));
  }

  /// TODO: add Challenge PreviousProp
  static previousPropositionChallengeContains (p: Challenge_PreviousProposition): ContainsImmutable {
    return this.transactionInputAddressContains(p.address).add(p.index.bImmutable());
  }

  static challengeContains (c: Challenge): ContainsImmutable {
    switch (c.proposition.case) {
      case 'revealed':
        return this.proposition(c.proposition.value);
      case 'previous':
        return this.previousPropositionChallengeContains(c.proposition.value);
      default:
        throw new Error('Invalid Challenge proposition: discriminated union returned never!');
    }
  }

  static eonEvent (event: Event_Eon): ContainsImmutable {
    return this.bigInt(event.beginSlot).add(this.bigInt(event.height));
  }

  static eraEvent (event: Event_Era): ContainsImmutable {
    return this.bigInt(event.beginSlot).add(this.bigInt(event.height));
  }

  static epochEvent (event: Event_Epoch): ContainsImmutable {
    return this.bigInt(event.beginSlot).add(this.bigInt(event.height));
  }

  static headerEvent (event: Event_Header): ContainsImmutable {
    return this.bigInt(event.height);
  }

  static iotxEventImmutable (event: Event_IoTransaction): ContainsImmutable {
    return this.iotxSchedule(event.schedule).add(this.smallData(event.metadata));
  }

  static groupPolicyEvent (eg: Event_GroupPolicy): ContainsImmutable {
    return this.string(eg.label)
      .add(this.seriesIdValue(eg.fixedSeries))
      .add(this.transactionOutputAddress(eg.registrationUtxo));
  }

  static seriesPolicyEvent (es: Event_SeriesPolicy): ContainsImmutable {
    if (
      typeof es === 'undefined' ||
      typeof es.tokenSupply === 'undefined' ||
      typeof es.label === 'undefined' ||
      typeof es.fungibility === 'undefined' ||
      typeof es.quantityDescriptor === 'undefined'
    ) {
      throw Error('SeriesPolicyEvent values are undefined');
    }
    return this.string(es.label)
      .add(this.number(es.tokenSupply))
      .add(this.transactionOutputAddress(es.registrationUtxo))
      .add(this.fungibility(es.fungibility))
      .add(this.quantityDescriptor(es.quantityDescriptor));
  }

  static eventImmutable (event: Event): ContainsImmutable {
    switch (event.value.case) {
      case 'eon':
        return this.eonEvent(event.value.value);
      case 'era':
        return this.eraEvent(event.value.value);
      case 'epoch':
        return this.epochEvent(event.value.value);
      case 'header':
        return this.headerEvent(event.value.value);
      case 'ioTransaction':
        return this.iotxEventImmutable(event.value.value);
      case 'groupPolicy':
        return this.groupPolicyEvent(event.value.value);
      case 'seriesPolicy':
        return this.seriesPolicyEvent(event.value.value);
      default:
        throw new Error(`Invalid Event type: discriminated union returned never!`);
    }
  }

  static txBind (txBind: TxBind): ContainsImmutable {
    return txBind.value.bImmutable();
  }

  static locked (_: Proposition_Locked): ContainsImmutable {
    return this.string(Tokens.locked);
  }

  static lockedProof (_: Proof_Locked): ContainsImmutable {
    return this.empty();
  }

  static digestProposition (p: Proposition_Digest): ContainsImmutable {
    return this.string(Tokens.digest).add(this.string(p.routine)).add(this.digest(p.digest));
  }

  static digestProof (p: Proof_Digest): ContainsImmutable {
    return this.txBind(p.transactionBind).add(this.preimage(p.preimage));
  }

  static signature (p: Proposition_DigitalSignature): ContainsImmutable {
    return this.string(Tokens.digitalSignature)
      .add(this.string(p.routine))
      .add(this.verificationKey(p.verificationKey));
  }

  static signatureProof (p: Proof_DigitalSignature): ContainsImmutable {
    return this.txBind(p.transactionBind).add(this.witness(p.witness));
  }

  static heightRange (p: Proposition_HeightRange): ContainsImmutable {
    return this.string(Tokens.heightRange).add(this.string(p.chain)).add(this.bigInt(p.min)).add(this.bigInt(p.max));
  }

  static heightRangeProof (p: Proof_HeightRange): ContainsImmutable {
    return this.txBind(p.transactionBind);
  }

  static tickRange (p: Proposition_TickRange): ContainsImmutable {
    return this.string(Tokens.tickRange).add(this.bigInt(p.min)).add(this.bigInt(p.max));
  }

  static tickRangeProof (p: Proof_TickRange): ContainsImmutable {
    return this.txBind(p.transactionBind);
  }

  static exactMatch (p: Proposition_ExactMatch): ContainsImmutable {
    return this.string(Tokens.exactMatch).add(this.string(p.location)).add(p.compareTo.bImmutable());
  }

  static exactMatchProof (p: Proof_ExactMatch): ContainsImmutable {
    return this.txBind(p.transactionBind);
  }

  static lessThan (p: Proposition_LessThan): ContainsImmutable {
    return this.string(Tokens.lessThan).add(this.string(p.location)).add(this.int128(p.compareTo));
  }

  static lessThanProof (p: Proof_LessThan): ContainsImmutable {
    return this.txBind(p.transactionBind);
  }

  static greaterThan (p: Proposition_GreaterThan): ContainsImmutable {
    return this.string(Tokens.greaterThan).add(this.string(p.location)).add(this.int128(p.compareTo));
  }

  static greaterThanProof (p: Proof_GreaterThan): ContainsImmutable {
    return this.txBind(p.transactionBind);
  }

  static equalTo (p: Proposition_EqualTo): ContainsImmutable {
    return this.string(Tokens.equalTo).add(this.string(p.location)).add(this.int128(p.compareTo));
  }

  static equalToProof (p: Proof_EqualTo): ContainsImmutable {
    return this.txBind(p.transactionBind);
  }

  static threshold (p: Proposition_Threshold): ContainsImmutable {
    return this.string(Tokens.threshold).add(p.threshold.bImmutable()).add(this.list(p.challenges));
  }

  static thresholdProof (p: Proof_Threshold): ContainsImmutable {
    return this.txBind(p.transactionBind).add(this.list(p.responses));
  }

  static not (p: Proposition_Not): ContainsImmutable {
    return this.string(Tokens.not).add(this.proposition(p.proposition));
  }

  static notProof (p: Proof_Not): ContainsImmutable {
    return this.txBind(p.transactionBind).add(this.proof(p.proof));
  }

  static and (p: Proposition_And): ContainsImmutable {
    return this.string(Tokens.and).add(this.proposition(p.left)).add(this.proposition(p.right));
  }

  static andProof (p: Proof_And): ContainsImmutable {
    return this.txBind(p.transactionBind).add(this.proof(p.left)).add(this.proof(p.right));
  }

  static or (p: Proposition_Or): ContainsImmutable {
    return this.string(Tokens.or).add(this.proposition(p.left)).add(this.proposition(p.right));
  }

  static orProof (p: Proof_Or): ContainsImmutable {
    return this.txBind(p.transactionBind).add(this.proof(p.left)).add(this.proof(p.right));
  }

  static proposition (p: Proposition): ContainsImmutable {
    switch (p.value.case) {
      case 'locked':
        return this.locked(p.value.value);
      case 'digest':
        return this.digestProposition(p.value.value);
      case 'digitalSignature':
        return this.signature(p.value.value);
      case 'heightRange':
        return this.heightRange(p.value.value);
      case 'tickRange':
        return this.tickRange(p.value.value);
      case 'exactMatch':
        return this.exactMatch(p.value.value);
      case 'lessThan':
        return this.lessThan(p.value.value);
      case 'greaterThan':
        return this.greaterThan(p.value.value);
      case 'equalTo':
        return this.equalTo(p.value.value);
      case 'threshold':
        return this.threshold(p.value.value);
      case 'not':
        return this.not(p.value.value);
      case 'and':
        return this.and(p.value.value);
      case 'or':
        return this.or(p.value.value);
      default:
        throw new Error(`Invalid Proposition type: discriminated union returned never!`);
    }
  }

  static proof (p: Proof): ContainsImmutable {
    switch (p.value.case) {
      case 'locked':
        return this.lockedProof(p.value.value);
      case 'digest':
        return this.digestProof(p.value.value);
      case 'digitalSignature':
        return this.signatureProof(p.value.value);
      case 'heightRange':
        return this.heightRangeProof(p.value.value);
      case 'tickRange':
        return this.tickRangeProof(p.value.value);
      case 'exactMatch':
        return this.exactMatchProof(p.value.value);
      case 'lessThan':
        return this.lessThanProof(p.value.value);
      case 'greaterThan':
        return this.greaterThanProof(p.value.value);
      case 'equalTo':
        return this.equalToProof(p.value.value);
      case 'threshold':
        return this.thresholdProof(p.value.value);
      case 'not':
        return this.notProof(p.value.value);
      case 'and':
        return this.andProof(p.value.value);
      case 'or':
        return this.orProof(p.value.value);
      default:
        return this.empty();
    }
  }

  static list (list: any[]): ContainsImmutable {
    return list.reduce((acc: ContainsImmutable, entry: any, index: number) => {
      const intResult = ContainsImmutable.number(index);
      const applyResult = ContainsImmutable.apply(entry);

      const partiallyCombinedContainsImmutable = acc.add(intResult);
      return partiallyCombinedContainsImmutable.add(applyResult);
    }, ContainsImmutable.empty());
  }

  /// dynamically handles processing for generic object
  /// consider using the direct type for better performance
  ///
  /// primarily implemented for the List function
  /// dart does not support proper type checking in switch statements
  /// ergo: A horrible if/else chain
  static apply (type: any): ContainsImmutable {
    if (type instanceof ContainsImmutable) {
      return type;
    } else if (type instanceof ImmutableBytes) {
      return new ContainsImmutable(type);
    }

    /// base types
    else if (Array.isArray(type) && typeof type[0] === 'number') {
      return ContainsImmutable.list(type.map((t: number) => t.bImmutableBytes()));
    } else if (type instanceof Uint8Array) {
      return type.bImmutable();
    } else if (typeof type === 'number') {
      return type.bImmutable();
    } else if (typeof type === 'string') {
      return ContainsImmutable.string(type);
    } else if (type instanceof BigInt || typeof type === 'bigint') {
      return ContainsImmutable.bigInt(type);
    } else if (type instanceof Int128) {
      return ContainsImmutable.int128(type);
    } else if (isOptionContainsImmutable(type)) {
      /// type check uses guard, which feels like a bad hack
      return ContainsImmutable.option(type);
    } else if (type instanceof SmallData) {
      return ContainsImmutable.smallData(type);
    } else if (type instanceof Root) {
      return ContainsImmutable.root(type);
    } else if (type instanceof ByteString) {
      return ContainsImmutable.byteString(type);
    } else if (type instanceof Struct) {
      return ContainsImmutable.struct(type);
    } else if (Array.isArray(type)) {
      return ContainsImmutable.list(type);
    }

    /// pb types
    /// Verification keys
    else if (type instanceof VerificationKey) {
      return ContainsImmutable.verificationKey(type);
    } else if (type instanceof Ed25519Vk) {
      return ContainsImmutable.ed25519VerificationKey(type);
    } else if (type instanceof ExtendedEd25519Vk) {
      return ContainsImmutable.extendedEd25519VerificationKey(type);
    }
    /// Datum Types
    else if (type instanceof Witness) {
      return ContainsImmutable.witness(type);
    } else if (type instanceof Datum) {
      return ContainsImmutable.datum(type);
    } else if (type instanceof Datum_Eon) {
      return ContainsImmutable.eonDatum(type);
    } else if (type instanceof Datum_Era) {
      return ContainsImmutable.eraDatum(type);
    } else if (type instanceof Datum_Epoch) {
      return ContainsImmutable.epochDatum(type);
    } else if (type instanceof Datum_Header) {
      return ContainsImmutable.headerDatum(type);
    } else if (type instanceof Datum_IoTransaction) {
      return ContainsImmutable.ioTransactionDatum(type);
    } else if (type instanceof Datum_GroupPolicy) {
      return ContainsImmutable.groupPolicyDatum(type);
    } else if (type instanceof Datum_SeriesPolicy) {
      return ContainsImmutable.seriesPolicyDatum(type);
    }
    /// Io Transactions
    else if (type instanceof IoTransaction) {
      return ContainsImmutable.ioTransaction(type);
    } else if (type instanceof Schedule) {
      return ContainsImmutable.iotxSchedule(type);
    } else if (type instanceof SpentTransactionOutput) {
      return ContainsImmutable.spentOutput(type);
    } else if (type instanceof UnspentTransactionOutput) {
      return ContainsImmutable.unspentOutput(type);
    } else if (type instanceof Box) {
      return ContainsImmutable.box(type);
    }
    /// levels
    else if (type instanceof Value) {
      return ContainsImmutable.value(type);
    } else if (type instanceof Lvl) {
      return ContainsImmutable.lvlValue(type);
    } else if (type instanceof Topl) {
      return ContainsImmutable.toplValue(type);
    } else if (type instanceof Asset) {
      return ContainsImmutable.assetValue(type);
    } else if (type instanceof Series) {
      return ContainsImmutable.seriesValue(type);
    } else if (type instanceof Group) {
      return ContainsImmutable.groupValue(type);
    } else if (type instanceof Ratio) {
      return ContainsImmutable.ratio(type);
    } else if (type instanceof Duration) {
      return ContainsImmutable.duration(type);
    } else if (type instanceof UpdateProposal) {
      return ContainsImmutable.updateProposal(type);
    }
    // extra
    else if (type instanceof Evidence) {
      return ContainsImmutable.evidence(type);
    } else if (type instanceof Digest) {
      return ContainsImmutable.digest(type);
    } else if (type instanceof Preimage) {
      return ContainsImmutable.preimage(type);
    } else if (type instanceof AccumulatorRootId) {
      return ContainsImmutable.accumulatorRoot32Identifier(type);
    } else if (type instanceof LockId) {
      return ContainsImmutable.boxLock32Identifier(type);
    } else if (type instanceof TransactionId) {
      return ContainsImmutable.transactionIdentifier(type);
    } else if (type instanceof GroupId) {
      return ContainsImmutable.groupIdentifier(type);
    } else if (type instanceof SeriesId) {
      return ContainsImmutable.seriesIdValue(type);
    } else if (type instanceof TransactionOutputAddress) {
      return ContainsImmutable.transactionOutputAddress(type);
    } else if (type instanceof LockAddress) {
      return ContainsImmutable.lockAddress(type);
    } else if (type instanceof StakingAddress) {
      return ContainsImmutable.stakingAddress(type);
    } else if (isFungibilityType(type)) {
      /// type check uses guard, which feels like a bad hack
      return ContainsImmutable.fungibility(type);
      /// type check uses guard, which feels like a bad hack
    } else if (isQuantityDescriptorType(type)) {
      return ContainsImmutable.quantityDescriptor(type);
    }
    /// signatures
    else if (type instanceof SignatureKesSum) {
      return ContainsImmutable.signatureKesSum(type);
    } else if (type instanceof SignatureKesProduct) {
      return ContainsImmutable.signatureKesProduct(type);
    } else if (type instanceof StakingRegistration) {
      return ContainsImmutable.stakingRegistration(type);
    } else if (type instanceof Lock_Predicate) {
      return ContainsImmutable.predicateLock(type);
    } else if (type instanceof Lock_Image) {
      return ContainsImmutable.imageLock(type);
    } else if (type instanceof Lock_Commitment) {
      return ContainsImmutable.commitmentLock(type);
    } else if (type instanceof Lock) {
      return ContainsImmutable.lock(type);
    } else if (type instanceof Attestation_Predicate) {
      return ContainsImmutable.predicateAttestation(type);
    } else if (type instanceof Attestation_Image) {
      return ContainsImmutable.imageAttestation(type);
    } else if (type instanceof Attestation_Commitment) {
      return ContainsImmutable.commitmentAttestation(type);
    } else if (type instanceof Attestation) {
      return ContainsImmutable.attestation(type);
    } else if (type instanceof TransactionInputAddress) {
      return ContainsImmutable.transactionInputAddressContains(type);
    } else if (type instanceof Challenge_PreviousProposition) {
      return ContainsImmutable.previousPropositionChallengeContains(type);
    } else if (type instanceof Challenge) {
      return ContainsImmutable.challengeContains(type);
    }
    /// events
    else if (type instanceof Event_Eon) {
      return ContainsImmutable.eonEvent(type);
    } else if (type instanceof Event_Era) {
      return ContainsImmutable.eraEvent(type);
    } else if (type instanceof Event_Epoch) {
      return ContainsImmutable.epochEvent(type);
    } else if (type instanceof Event_Header) {
      return ContainsImmutable.headerEvent(type);
    } else if (type instanceof Event_IoTransaction) {
      return ContainsImmutable.iotxEventImmutable(type);
    } else if (type instanceof Event) {
      return ContainsImmutable.eventImmutable(type);
    } else if (type instanceof TxBind) {
      return ContainsImmutable.txBind(type);
    }
    /// Propositions and Proofs
    else if (type instanceof Proposition_Locked) {
      return ContainsImmutable.locked(type);
    } else if (type instanceof Proof_Locked) {
      return ContainsImmutable.lockedProof(type);
    } else if (type instanceof Proposition_Digest) {
      return ContainsImmutable.digestProposition(type);
    } else if (type instanceof Proof_Digest) {
      return ContainsImmutable.digestProof(type);
    } else if (type instanceof Proposition_DigitalSignature) {
      return ContainsImmutable.signature(type);
    } else if (type instanceof Proof_DigitalSignature) {
      return ContainsImmutable.signatureProof(type);
    } else if (type instanceof Proposition_HeightRange) {
      return ContainsImmutable.heightRange(type);
    } else if (type instanceof Proof_HeightRange) {
      return ContainsImmutable.heightRangeProof(type);
    } else if (type instanceof Proposition_TickRange) {
      return ContainsImmutable.tickRange(type);
    } else if (type instanceof Proof_TickRange) {
      return ContainsImmutable.tickRangeProof(type);
    } else if (type instanceof Proposition_ExactMatch) {
      return ContainsImmutable.exactMatch(type);
    } else if (type instanceof Proof_ExactMatch) {
      return ContainsImmutable.exactMatchProof(type);
    } else if (type instanceof Proposition_LessThan) {
      return ContainsImmutable.lessThan(type);
    } else if (type instanceof Proof_LessThan) {
      return ContainsImmutable.lessThanProof(type);
    } else if (type instanceof Proposition_GreaterThan) {
      return ContainsImmutable.greaterThan(type);
    } else if (type instanceof Proof_GreaterThan) {
      return ContainsImmutable.greaterThanProof(type);
    } else if (type instanceof Proposition_EqualTo) {
      return ContainsImmutable.equalTo(type);
    } else if (type instanceof Proof_EqualTo) {
      return ContainsImmutable.equalToProof(type);
    } else if (type instanceof Proposition_Threshold) {
      return ContainsImmutable.threshold(type);
    } else if (type instanceof Proof_Threshold) {
      return ContainsImmutable.thresholdProof(type);
    } else if (type instanceof Proposition_Not) {
      return ContainsImmutable.not(type);
    } else if (type instanceof Proof_Not) {
      return ContainsImmutable.notProof(type);
    } else if (type instanceof Proposition_And) {
      return ContainsImmutable.and(type);
    } else if (type instanceof Proof_And) {
      return ContainsImmutable.andProof(type);
    } else if (type instanceof Proposition_Or) {
      return ContainsImmutable.or(type);
    } else if (type instanceof Proof_Or) {
      return ContainsImmutable.orProof(type);
    } else if (type instanceof Proposition) {
      return ContainsImmutable.proposition(type);
    } else if (type instanceof Proof) {
      return ContainsImmutable.proof(type);
    } else {
      throw new Error(`Somehow Invalid type passed to Apply: ${type.constructor.name} `);
    }
  }

  /// primitive apply method
  static applyOld (t: any): ContainsImmutable {
    if (t instanceof ContainsImmutable) {
      return t;
    }
    if (t instanceof ImmutableBytes) {
      return new ContainsImmutable(t);
    }
    if (t instanceof Lock) {
      return ContainsImmutable.lock(t);
    }
    if (t instanceof Lock_Predicate) {
      return ContainsImmutable.predicateLock(t);
    }
  }

  /**
   * Adds a `ContainsImmutable` object to the current `ContainsImmutable` instance.
   *
   * @param b - The `ContainsImmutable` object to be added.
   * @returns A new `ContainsImmutable` instance with the added object.
   */
  add (b: ContainsImmutable): ContainsImmutable {
    return _addContainsImmutable(this, b);
  }
}

// private operations
function _addImmutableBytes (a: ImmutableBytes, b: ImmutableBytes): ImmutableBytes {
  const mergedArray = new Uint8Array(a.value.length + b.value.length);
  mergedArray.set(a.value);
  mergedArray.set(b.value, a.value.length);
  return new ImmutableBytes({ value: mergedArray });
}

function _addContainsImmutable (a: ContainsImmutable, b: ContainsImmutable): ContainsImmutable {
  return new ContainsImmutable(_addImmutableBytes(a.immutableBytes, b.immutableBytes));
}

/**
 * Converts a Uint8Array to an ImmutableBytes object.
 * used to prevent cyclic dependencies with the extension methods this file should prioritize this function for Uint8Arrays.
 *
 * @param uInt8Array - The Uint8Array to convert.
 * @returns An ImmutableBytes object.
 */
function _Uint8ArrayToImmutableBytes (uInt8Array: Uint8Array): ImmutableBytes {
  return new ImmutableBytes({ value: uInt8Array });
}

/// experimental extensions via typescript module augmentation on Topl Common
declare module 'topl_common' {
  interface ImmutableBytes {
    /**
     * Adds a `ImmutableBytes` object to the current `ImmutableBytes` instance.
     *
     * @param b - The `ImmutableBytes` object to be added.
     * @returns A new `ImmutableBytes` instance with the added object.
     */
    add(b: ImmutableBytes): ImmutableBytes;
    /**
     * Converts to a ContainsImmutable instance.
     */
    immutable(): ContainsImmutable;
  }
}

ImmutableBytes.prototype.add = function (b: ImmutableBytes) {
  return _addImmutableBytes(this, b);
};

ImmutableBytes.prototype.immutable = function () {
  return new ContainsImmutable(this);
};

/// experimental extensions via typescript module augmentation on global scope, warnings from extensions_exp.ts apply
declare global {
  interface Number {
    /**
     * Converts the number to an ImmutableBytes instance.
     * @returns An ImmutableBytes instance representing the number.
     */
    bImmutableBytes?(): ImmutableBytes;

    /**
     * Converts the number to a ContainsImmutable instance.
     * @returns A ContainsImmutable instance representing the number.
     */
    bImmutable?(): ContainsImmutable;
  }

  interface Uint8Array {
    /**
     * Converts the Uint8Array to an ImmutableBytes instance.
     * @returns An ImmutableBytes instance representing the Uint8Array.
     */
    bImmutableBytes?(): ImmutableBytes;

    /**
     * Converts the Uint8Array to a ContainsImmutable instance.
     * @returns A ContainsImmutable instance representing the Uint8Array.
     */
    bImmutable?(): ContainsImmutable;
  }
  interface Array<T> {
    /**
     * Converts the array to an ImmutableBytes instance.
     * @returns An ImmutableBytes instance representing the array.
     */
    bImmutableBytes?(): ImmutableBytes;

    /**
     * Converts the array to a ContainsImmutable instance.
     * @returns A ContainsImmutable instance representing the array.
     */
    bImmutable?(): ContainsImmutable;
  }
}

// Number
Number.prototype.bImmutableBytes = function () {
  return this.bImmutable.immutableBytes;
};

Number.prototype.bImmutable = function () {
  if (this !== null) return ContainsImmutable.number(this);
  // return
};

// Uint8Array
Uint8Array.prototype.bImmutableBytes = function () {
  return _Uint8ArrayToImmutableBytes(this);
};

Uint8Array.prototype.bImmutable = function () {
  return ContainsImmutable.uInt8Array(this);
};

// Arrays
Array.prototype.bImmutableBytes = function () {
  return ContainsImmutable.list(this).immutableBytes;
};

Array.prototype.bImmutable = function () {
  return ContainsImmutable.list(this);
};
