import { isLeft, left, right, type Either } from '@/common/functional/either.js';
import {
  Attestation,
  Attestation_Predicate,
  Datum_GroupPolicy,
  Datum_IoTransaction,
  Datum_SeriesPolicy,
  Event_GroupPolicy,
  Event_IoTransaction,
  Event_SeriesPolicy,
  Group,
  GroupId,
  Int128,
  IoTransaction,
  Lock,
  LockAddress,
  LockId,
  Lock_Predicate,
  Lvl,
  Proof,
  Schedule,
  Series,
  SpentTransactionOutput,
  TransactionOutputAddress,
  Txo,
  UnspentTransactionOutput,
  Value
} from 'topl_common';
import { unit, type Unit } from '../../common/functional.js';
import { AddressCodecs } from '../codecs/address_codec.js';
import { ContainsEvidence } from '../common/contains_evidence.js';
import { GroupPolicySyntax } from '../syntax/group_policy_syntax.js';
import { Uint8ArrayUtils } from '../utils/extensions.js';
import { BuilderError } from './builder_error.js';

abstract class TransactionBuilderApi {
  abstract unprovenAttenstation(lockPredicate: Lock_Predicate): Attestation;
  abstract lockAddress(lock: Lock): LockAddress;
  abstract lvlOutput(predicate: Lock_Predicate, amount: Int128): UnspentTransactionOutput;
  abstract lvlOutputWithLockAddress(lockAddress: LockAddress, amount: Int128): UnspentTransactionOutput;
  abstract datum(): Datum_IoTransaction;
  abstract buildSimpleLvlTransaction(
    lvlTxos: Txo[],
    lockPredicateFrom: Lock_Predicate,
    lockPredicateForChange: Lock_Predicate,
    recipientLockAddress: LockAddress,
    amount: number
  ): IoTransaction;
  abstract buildSimpleGroupMintingTransaction(
    registrationTxo: Txo,
    registrationLock: Lock_Predicate,
    groupPolicy: Event_GroupPolicy,
    quantityToMint: Int128,
    mintedConstructorLockAddress: LockAddress
  ): Either<BuilderError, IoTransaction>;
  abstract buildSimpleSeriesMintingTransaction(
    registrationTxo: Txo,
    registrationLock: Lock_Predicate,
    seriesPolicy: Event_SeriesPolicy,
    quantityToMint: Int128,
    mintedConstructorLockAddress: LockAddress
  ): Either<BuilderError, IoTransaction>;
}

export class transactionBuilderApiImpl implements TransactionBuilderApi {
  public networkId: number;
  public ledgerId: number;

  constructor (networkId: number, ledgerId: number) {
    this.networkId = networkId;
    this.ledgerId = ledgerId;
  }

  unprovenAttenstation (lockPredicate: Lock_Predicate): Attestation {
    return new Attestation({
      value: {
        case: 'predicate',
        value: new Attestation_Predicate({
          lock: lockPredicate,
          responses: new Array(lockPredicate.challenges.length).fill(new Proof())
        })
      }
    });
  }

  lockAddress (lock: Lock): LockAddress {
    return new LockAddress({
      network: this.networkId,
      ledger: this.ledgerId,
      id: new LockId({
        value: ContainsEvidence.blake2bEvidenceFromImmutable(lock).evidence.digest.value
      })
    });
  }

  lvlOutput (predicate: Lock_Predicate, amount: Int128): UnspentTransactionOutput {
    return new UnspentTransactionOutput({
      address: new LockAddress({
        network: this.networkId,
        ledger: this.ledgerId,
        id: new LockId({
          value: ContainsEvidence.blake2bEvidenceFromImmutable(
            new Lock({ value: { case: 'predicate', value: predicate } })
          ).evidence.digest.value
        })
      }),
      value: new Value({ value: { case: 'lvl', value: new Lvl({ quantity: amount }) } })
    });
  }

  lvlOutputWithLockAddress (lockAddress: LockAddress, amount: Int128): UnspentTransactionOutput {
    return new UnspentTransactionOutput({
      address: lockAddress,
      value: new Value({
        value: {
          case: 'lvl',
          value: new Lvl({
            quantity: amount
          })
        }
      })
    });
  }

  datum (): Datum_IoTransaction {
    return new Datum_IoTransaction({
      event: new Event_IoTransaction({
        schedule: new Schedule({
          min: BigInt(0),
          max: BigInt(Number.MAX_VALUE),
          timestamp: BigInt(Date.now())
        })
      })
    });
  }

  unprovenAttestation (predicate: Lock_Predicate): Attestation {
    return new Attestation({
      value: {
        case: 'predicate',
        value: new Attestation_Predicate({
          lock: predicate,
          responses: Array.from({ length: predicate.challenges.length }, () => new Proof())
        })
      }
    });
  }

  buildSimpleLvlTransaction (
    lvlTxos: Txo[],
    lockPredicateFrom: Lock_Predicate,
    lockPredicateForChange: Lock_Predicate,
    recipientLockAddress: LockAddress,
    amount: number
  ): IoTransaction {
    const unprovenAttestationToProve = this.unprovenAttenstation(lockPredicateFrom);
    const totalValues = lvlTxos.reduce((acc, x) => {
      const y = x.transactionOutput.value;
      return y.value.case === 'lvl' && y.value.value.quantity !== null
        ? acc + Uint8ArrayUtils.toBigInt(y.value.value.quantity.value)
        : acc;
    }, BigInt(0));

    const d = this.datum();
    const textEncoder = new TextEncoder();

    const encodedDataForChange = textEncoder.encode((totalValues - BigInt(amount)).toString());
    const lvlOutputForChange = this.lvlOutput(
      lockPredicateForChange,
      new Int128({ value: new Uint8Array(encodedDataForChange) })
    );
    const encodedDataForRecipient = textEncoder.encode(amount.toString());
    const lvlOutputForRecipient = this.lvlOutputWithLockAddress(
      recipientLockAddress,
      new Int128({ value: new Uint8Array(encodedDataForRecipient) })
    );
    const ioTransaction = new IoTransaction();
    ioTransaction.inputs = lvlTxos.map(x => {
      return new SpentTransactionOutput({
        address: x.outputAddress,
        attestation: unprovenAttestationToProve,
        value: x.transactionOutput.value
      });
    });
    ioTransaction.outputs =
      totalValues - BigInt(amount) > BigInt(0) ? [lvlOutputForRecipient, lvlOutputForChange] : [lvlOutputForRecipient];
    ioTransaction.datum = d;
    return ioTransaction;
  }

  buildSimpleGroupMintingTransaction (
    registrationTxo: Txo,
    registrationLock: Lock_Predicate,
    groupPolicy: Event_GroupPolicy,
    quantityToMint: Int128,
    mintedConstructorLockAddress: LockAddress
  ): Either<BuilderError, IoTransaction> {
    const lock = new Lock({ value: { case: 'predicate', value: registrationLock } });
    const registrationLockAddr = new LockAddress({
      network: this.networkId,
      ledger: this.ledgerId,
      id: new LockId({
        value: ContainsEvidence.blake2bEvidenceFromImmutable(lock).evidence.digest.value
      })
    });
    const validationResult = this.validateConstructorMintingParams(
      registrationTxo,
      registrationLockAddr,
      groupPolicy.registrationUtxo,
      quantityToMint
    );
    if (isLeft(validationResult)) {
      return left(
        new UnableToBuildTransaction(
          'Unable to build transaction to mint group constructor tokens',
          validationResult.left
        )
      );
    }
    const stxoAttestation = this.unprovenAttestation(registrationLock);
    const d = this.datum();
    const utxoMinted = this.groupOutput(
      mintedConstructorLockAddress,
      quantityToMint,
      new GroupPolicySyntax(groupPolicy).computeId()
    );
    return right(
      new IoTransaction({
        inputs: [
          new SpentTransactionOutput({
            address: registrationTxo.outputAddress,
            attestation: stxoAttestation,
            value: registrationTxo.transactionOutput.value
          })
        ],
        outputs: [utxoMinted],
        datum: d,
        groupPolicies: [new Datum_GroupPolicy({ event: groupPolicy })]
      })
    );
  }

  buildSimpleSeriesMintingTransaction (
    registrationTxo: Txo,
    registrationLock: Lock_Predicate,
    seriesPolicy: Event_SeriesPolicy,
    quantityToMint: Int128,
    mintedConstructorLockAddress: LockAddress
  ): Either<BuilderError, IoTransaction> {
    const lock = new Lock({ value: { case: 'predicate', value: registrationLock } });
    const registrationLockAddr = new LockAddress({
      network: this.networkId,
      ledger: this.ledgerId,
      id: new LockId({
        value: ContainsEvidence.blake2bEvidenceFromImmutable(lock).evidence.digest.value
      })
    });
    const validationResult = this.validateConstructorMintingParams(
      registrationTxo,
      registrationLockAddr,
      seriesPolicy.registrationUtxo,
      quantityToMint
    );
    if (isLeft(validationResult)) {
      return left(
        new UnableToBuildTransaction(
          'Unable to build transaction to mint series constructor tokens',
          validationResult.left
        )
      );
    }
    const stxoAttestation = this.unprovenAttestation(registrationLock);
    const d = this.datum();
    const utxoMinted = this.seriesOutput(mintedConstructorLockAddress, quantityToMint, seriesPolicy);
    return right(
      new IoTransaction({
        inputs: [
          new SpentTransactionOutput({
            address: registrationTxo.outputAddress,
            attestation: stxoAttestation,
            value: registrationTxo.transactionOutput.value
          })
        ],
        outputs: [utxoMinted],
        datum: d,
        seriesPolicies: [new Datum_SeriesPolicy({ event: seriesPolicy })]
      })
    );
  }

  validateConstructorMintingParams (
    registrationTxo: Txo,
    registrationLockAddr: LockAddress,
    policyRegistrationUtxo: TransactionOutputAddress,
    quantityToMint: Int128
  ): Either<UserInputError, Unit> {
    if (registrationTxo.outputAddress !== policyRegistrationUtxo) {
      return left(new UserInputError('registrationTxo does not match registrationUtxo'));
    } else if (registrationTxo.transactionOutput.value.value.case !== 'lvl') {
      return left(new UserInputError('registrationUtxo does not contain LVLs'));
    } else if (registrationLockAddr != registrationTxo.transactionOutput.address) {
      return left(new UserInputError('registrationLock does not correspond to registrationTxo'));
    } else if (
      AddressCodecs.uint8ArrayToNumber(quantityToMint.value) < 0 ||
      AddressCodecs.uint8ArrayToNumber(quantityToMint.value) === 0
    ) {
      return left(new UserInputError('quantityToMint must be positive'));
    } else {
      return right(unit);
    }
  }

  groupOutput (lockAddress: LockAddress, quantity: Int128, groupId: GroupId): UnspentTransactionOutput {
    const group = new Group({
      groupId: groupId,
      quantity: quantity
    });
    return new UnspentTransactionOutput({
      address: lockAddress,
      value: {
        value: {
          case: 'group',
          value: group
        }
      }
    });
  }

  seriesOutput (lockAddress: LockAddress, quantity: Int128, policy: Event_SeriesPolicy): UnspentTransactionOutput {
    const value = new Series({
      seriesId: {
        value: policy.computeId().value
      },
      quantity: quantity,
      tokenSupply: policy.tokenSupply,
      quantityDescriptor: policy.quantityDescriptor,
      fungibility: policy.fungibility
    });
    return new UnspentTransactionOutput({
      address: lockAddress,
      value: {
        value: {
          case: 'series',
          value: value
        }
      }
    });
  }
}

export class LockAddressOps {
  public lockAddress: LockAddress;

  constructor (lockAddress: LockAddress) {
    this.lockAddress = lockAddress;
  }

  toBase58 (): string {
    return AddressCodecs.encode(this.lockAddress);
  }
}

class UserInputError extends BuilderError {
  constructor (message: string) {
    super(message);
  }
}

class UnableToBuildTransaction extends BuilderError {
  constructor (message: string, exception: Error) {
    super(message, { exception });
  }
}
