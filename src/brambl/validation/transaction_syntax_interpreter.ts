import {
  AssetMintingStatement,
  FungibilityType,
  Group,
  IoTransaction,
  Lock_Predicate,
  Proof,
  Proposition,
  Series,
  UnspentTransactionOutput,
  Value,
  type Int128,
  type SpentTransactionOutput,
  type TransactionOutputAddress
} from 'topl_common';
import { ContainsImmutable } from '../common/contains_immutable.js';
import { BoxValueSyntax } from '../syntax/box_value_syntax.js';
import Int128Syntax from '../syntax/int128_syntax.js';
import {
  DuplicateInput,
  EmptyInputs,
  ExcessiveOutputsCount,
  InsufficientInputFunds,
  InvalidDataLength,
  InvalidProofType,
  InvalidSchedule,
  InvalidTimestamp,
  InvalidUpdateProposal,
  NonPositiveOutputValue,
  TransactionSyntaxError
} from './transaction_syntax_error.js';
import { isLeft, left, right, unit, type Either, type Unit } from '@/common/functional/brambl_fp.js';

class TransactionSyntaxValidators {
  static readonly MaxDataLength = 15360;

  /**
   * Verify that this transaction contains at least one input
   */
  static nonEmptyInputsValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    if (transaction.inputs.length === 0) {
      return left(new EmptyInputs());
    } else {
      return right(unit);
    }
  }

  /**
   * Verify that this transaction does not spend the same box more than once
   */
  static distinctInputsValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    //Todo: figure out if this is a good grouping implementation
    const groupedInputs = transaction.inputs.reduce((acc, input) => {
      const existingInputs = acc.get(input.address) || [];
      acc.set(input.address, [...existingInputs, input]);
      return acc;
    }, new Map<TransactionOutputAddress, SpentTransactionOutput[]>());

    for (const address in groupedInputs) {
      if (groupedInputs[address] > 1) {
        return left(new DuplicateInput(groupedInputs[address]));
      }
    }

    return right(unit);
  }

  /**
   * Verify that this transaction does not contain too many outputs. A transaction's outputs are referenced by index,
   * but that index must be a number value.
   */
  static maximumOutputsCountValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    const SHORT_MAX_VALUE = 32767;

    if (transaction.outputs.length >= SHORT_MAX_VALUE) {
      return left(new ExcessiveOutputsCount());
    } else {
      return right(unit);
    }
  }

  /**
   * Verify that the timestamp of the transaction is positive (greater than or equal to 0). Transactions _can_ be created
   * in the past.
   */
  static nonNegativeTimestampValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    if (transaction.datum.event.schedule.timestamp < 0) {
      return left(new InvalidTimestamp(transaction.datum.event.schedule.timestamp));
    } else {
      return right(unit);
    }
  }

  /**
   * Verify that the schedule of the timestamp contains valid minimum and maximum slot values
   */
  static scheduleValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    if (
      transaction.datum.event.schedule.max < transaction.datum.event.schedule.min ||
      transaction.datum.event.schedule.min < 0
    ) {
      return left(new InvalidSchedule(transaction.datum.event.schedule));
    } else {
      return right(unit);
    }
  }

  /**
   * Verify that each transaction output contains a positive quantity (where applicable)
   */
  static positiveOutputValuesValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    for (const output of transaction.outputs) {
      let quantity: Int128;

      switch (output.value.value.case) {
        case 'lvl':
          quantity = output.value.value.value.quantity;
          break;
        case 'topl':
          quantity = output.value.value.value.quantity;
          break;
        case 'asset':
          quantity = output.value.value.value.quantity;
          break;
      }

      // TODO: replace with updated accessor
      //       let quantity: Int128 = output.value.quantity();

      if (quantity !== null && Int128Syntax.int128AsBigInt(quantity).valueOf() <= BigInt(0).valueOf()) {
        return left(new NonPositiveOutputValue(output.value));
      }
    }

    return right(unit);
  }

  /**
   * Verify that the transaction has sufficient funds to cover the outputs
   */
  private static getQuantity (value: Value): bigint {
    /// TODO: update this code segment with improvement
    // return value.quantity().bAsBigInt();

    switch (value.value.case) {
      case 'lvl':
        return Int128Syntax.int128AsBigInt(value.value.value.quantity);
      case 'topl':
        return Int128Syntax.int128AsBigInt(value.value.value.quantity);
      case 'asset':
        return Int128Syntax.int128AsBigInt(value.value.value.quantity);
      case 'series':
        return Int128Syntax.int128AsBigInt(value.value.value.quantity);
      case 'group':
        return Int128Syntax.int128AsBigInt(value.value.value.quantity);
      case 'updateProposal':
        // TODO: evaluate if this switch is right
        return BigInt(0);
      default:
        throw new Error(`Unexpected value type: returned NEVER`);
    }
  }

  /**
   * Ensure the input value quantities exceed or equal the (non-minting) output value quantities
   */
  static sufficientFundsValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    const sumAll = (values: Value[]): bigint => {
      if (values.length === 0) return BigInt(0);
      return values
        .map(value => this.getQuantity(value))
        .reduce((a, b) => a.valueOf() + b.valueOf())
        .valueOf();
    };

    const inputsSum = sumAll(transaction.inputs.map(input => input.value));
    const outputsSum = sumAll(transaction.outputs.map(output => output.value));

    return inputsSum >= outputsSum
      ? right(unit)
      : left(
          new InsufficientInputFunds(
            transaction.inputs.map(input => input.value),
            transaction.outputs.map(output => output.value)
          )
        );
  }

  /**
   * Validates that the attestations for each of the transaction's inputs are valid
   */
  static attestationValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    for (const input of transaction.inputs) {
      switch (input.attestation.value.case) {
        case 'predicate':
          const { lock, responses } = input.attestation.value.value;
          const result = this.predicateLockProofTypeValidation(lock, responses);
          if (isLeft(result)) {
            return result;
          }
          break;
        // TODO: There is no validation for Attestation types other than Predicate for now
        default:
          break;
      }
    }
    return right(unit);
  }

  /**
   * Validates that the proofs associated with each proposition matches the expected _type_ for a Predicate Attestation
   *
   * (i.e. a DigitalSignature Proof that is associated with a HeightRange Proposition, this validation will fail)
   *
   * Preconditions: lock.challenges.length <= responses.length
   */
  private static predicateLockProofTypeValidation (
    lock: Lock_Predicate,
    responses: Proof[]
  ): Either<TransactionSyntaxError, Unit> {
    const challengesAndResponses = lock.challenges
      .filter(challenge => challenge.proposition.case === 'revealed')
      .map((challenge, index) => {
        /// already checked, but type needs promotion
        if (challenge.proposition.case !== 'revealed') {
          throw new Error('Unexpected challenge proposition type');
        }
        return { challenge: challenge.proposition.value, response: responses[index] };
      });

    for (const { challenge, response } of challengesAndResponses) {
      const result = this.proofTypeMatch(challenge, response);
      if (isLeft(result)) {
        return result;
      }
    }

    return right(unit);
  }

  /**
   * Validate that the type of Proof matches the type of the given Proposition
   * A Proof.Value.Empty type is considered valid for all Proposition types
   */
  private static proofTypeMatch (proposition: Proposition, proof: Proof): Either<TransactionSyntaxError, Unit> {
    if (proof.value === null && proposition.value === null) {
      // Empty proofs are valid for all Proposition types
      return right(unit);
    }

    return left(new InvalidProofType(proposition, proof));
  }

  /**
   * DataLengthValidation validates approved transaction data length, includes proofs
   * @see [[https://topl.atlassian.net/browse/BN-708]]
   * @param transaction transaction
   * @return
   */
  static dataLengthValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    if (
      ContainsImmutable.ioTransaction(transaction).immutableBytes.value.length <=
      TransactionSyntaxValidators.MaxDataLength
    ) {
      return right(unit);
    } else {
      return left(new InvalidDataLength());
    }
  }

  /**
   * AssetEqualFundsValidation For each asset: input assets + minted assets == output asset
   * @param transaction - transaction
   * @return
   */
  static assetEqualFundsValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    const inputAssets = transaction.inputs
      .filter(input => input.value.value.case === 'asset')
      .map(input => {
        // type promotion
        if (input.value.value.case === 'asset') return BoxValueSyntax.assetAsBoxVal(input.value.value.value);
      });

    const outputAssets = transaction.outputs
      .filter(output => output.value.value.case === 'asset')
      .map(output => {
        // type promotion
        if (output.value.value.case === 'asset') return BoxValueSyntax.assetAsBoxVal(output.value.value.value);
      });

    const groupGivenMintedStatements = (stm: AssetMintingStatement): Group => {
      return transaction.inputs
        .filter(input => input.address === stm.groupTokenUtxo && input.value.value.case === 'group')
        .map(input => {
          // type promotion
          if (input.value.value.case === 'group') return input.value.value.value;
        })[0];
    };

    const seriesGivenMintedStatements = (stm: AssetMintingStatement): Series => {
      return transaction.inputs
        .filter(input => input.address === stm.seriesTokenUtxo && input.value.value.case === 'series')
        .map(input => {
          // type promotion
          if (input.value.value.case === 'series') return input.value.value.value;
        })[0];
    };

    const mintedAsset = transaction.mintingStatements.map(stm => {
      const series = seriesGivenMintedStatements(stm);
      return new Value({
        value: {
          case: 'asset',
          value: {
            groupId: groupGivenMintedStatements(stm)?.groupId,
            seriesId: series?.seriesId,
            quantity: stm.quantity,
            fungibility: series?.fungibility || FungibilityType.GROUP_AND_SERIES
          }
        }
      });
    });

    const tupleAndGroup = (s: Value[]): Either<Error, { [key: string]: bigint }> => {
      try {
        const grouped: { [key: string]: bigint[] } = {};

        for (const v of s) {
          const key = `${v.typeIdentifier}-${v.getFungibility()}-${v.getQuantityDescriptor()}`;

          if (!grouped[key]) {
            grouped[key] = [];
          }

          const add = v.quantity().asbigint();
          grouped[key].push(add);
        }

        const summed: { [key: string]: bigint } = {};

        for (const key in grouped) {
          summed[key] = grouped[key].reduce((a, b) => a + b, BigInt(0));
        }

        return right(summed);
      } catch (e) {
        return left(e);
      }
    };

    const input = tupleAndGroup(inputAssets);
    const minted = tupleAndGroup(mintedAsset);
    const output = tupleAndGroup(outputAssets);

    if (isLeft(input) || isLeft(minted) || isLeft(output)) {
      return left(
        new InsufficientInputFunds(
          transaction.inputs.map(input => input.value),
          transaction.outputs.map(output => output.value)
        )
      );
    }

    const keySetResult =
      new Set([...Object.keys(input.right), ...Object.keys(minted.right)]).size === Object.keys(output.right).length;
    const compareResult = Object.keys(output.right).every(
      k => (input.right[k] || BigInt(0)) + (minted.right[k] || BigInt(0)) === output.right[k]
    );

    return keySetResult && compareResult
      ? right(unit)
      : left(
          new InsufficientInputFunds(
            transaction.inputs.map(input => input.value),
            transaction.outputs.map(output => output.value)
          )
        );
  }

  /**
   * GroupEqualFundsValidation
   *
   *  - Check Moving Constructor Tokens: Let 'g' be a group identifier, then the number of Group Constructor Tokens with group identifier 'g'
   *    in the input is equal to the quantity of Group Constructor Tokens with identifier 'g' in the output.
   *  - Check Minting Constructor Tokens: Let 'g' be a group identifier and 'p' the group policy whose digest is equal to 'g', a transaction is valid only if the all of the following statements are true:
   *   - The policy 'p' is attached to the transaction.
   *   - The number of group constructor tokens with identifier 'g' in the output of the transaction is strictly bigger than 0.
   *   - The registration UTXO referenced in 'p' is present in the inputs and contains LVLs.
   *
   * @param transaction - transaction
   * @return
   */
  static groupEqualFundsValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    const groupsIn = transaction.inputs
      .filter(i => i.value.value.case === 'group')
      .flatMap(input => {
        // need to promote value after safety filtering
        if (input.value.value.case === 'group') {
          return input.value.value.value;
        }
      });

    const groupsOut = transaction.outputs
      .filter(i => i.value.value.case === 'group')
      .flatMap(output => {
        // need to promote value after safety filtering
        if (output.value.value.case === 'group') {
          return output.value.value.value;
        }
      });

    const gIds = new Set([
      ...groupsIn.map(group => group.groupId),
      ...groupsOut.map(group => group.groupId),
      ...transaction.groupPolicies.map(policy => {
        return policy.event.computeId();
      })
    ]);

    const res = Array.from(gIds).every(gId => {
      if (
        !transaction.groupPolicies
          .map(policy => {
            return policy.event.computeId();
          })
          .includes(gId)
      ) {
        return (
          groupsIn
            .filter(group => group.groupId === gId)
            .reduce((sum, group) => sum + Int128Syntax.int128AsBigInt(group.quantity).valueOf(), BigInt(0)) ===
          groupsOut
            .filter(group => group.groupId === gId)
            .reduce((sum, group) => sum + Int128Syntax.int128AsBigInt(group.quantity).valueOf(), BigInt(0))
        );
      } else {
        return (
          groupsOut
            .filter(group => group.groupId === gId)
            .reduce((sum, group) => sum + Int128Syntax.int128AsBigInt(group.quantity).valueOf(), BigInt(0)) > BigInt(0)
        );
      }
    });

    if (res) {
      return right(unit);
    } else {
      return left(
        new InsufficientInputFunds(
          transaction.inputs.map(input => input.value),
          transaction.outputs.map(output => output.value)
        )
      );
    }
  }

  /**
   * SeriesEqualFundsValidation
   *  - Check Moving Series Tokens: Let s be a series identifier, then the number of Series Constructor Tokens with group identifier s
   * in the input is equal to the number of the number of Series Constructor Tokens with identifier s in the output.
   *  - Check Minting Constructor Tokens: Let s be a series identifier and p the series policy whose digest is equal to s, all of the following statements are true:
   *    The policy p is attached to the transaction.
   *    The number of series constructor tokens with identifiers in the output of the transaction is strictly bigger than 0.
   *    The registration UTXO referenced in p is present in the inputs and contains LVLs.
   *
   * @param transaction
   * @return
   */
  static seriesEqualFundsValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    const seriesIn = transaction.inputs
      .filter(i => i.value.value.case === 'series')
      .flatMap(input => {
        if (input.value.value.case === 'series') {
          return input.value.value.value;
        }
      });
    const seriesOut = transaction.outputs
      .filter(i => i.value.value.case === 'series')
      .flatMap(output => {
        if (output.value.value.case === 'series') {
          return output.value.value.value;
        }
      });

    const sIds = new Set([
      ...seriesIn.map(series => series.seriesId),
      ...seriesOut.map(series => series.seriesId),
      ...transaction.seriesPolicies.map(policy => policy.event.computeId())
    ]);

    const sIdsOnMintingStatements = transaction.inputs
      .filter(
        input =>
          transaction.mintingStatements.map(statement => statement.seriesTokenUtxo).includes(input.address) &&
          input.value.value.case === 'series'
      )
      .map(input => {
        if (input.value.value.case === 'series') {
          return input.value.value.value.seriesId;
        }
      });

    const res = Array.from(sIds).every(sId => {
      if (sIdsOnMintingStatements.includes(sId)) {
        return (
          seriesOut
            .filter(series => series.seriesId === sId)
            .reduce((sum, series) => sum + Int128Syntax.int128AsBigInt(series.quantity).valueOf(), BigInt(0)) >=
          BigInt(0)
        );
      } else if (!transaction.seriesPolicies.map(policy => policy.event.computeId()).includes(sId)) {
        return (
          seriesIn
            .filter(series => series.seriesId === sId)
            .reduce((sum, series) => sum + Int128Syntax.int128AsBigInt(series.quantity).valueOf(), BigInt(0)) ===
          seriesOut
            .filter(series => series.seriesId === sId)
            .reduce((sum, series) => sum + Int128Syntax.int128AsBigInt(series.quantity).valueOf(), BigInt(0))
        );
      } else {
        return (
          seriesOut
            .filter(series => series.seriesId === sId)
            .reduce((sum, series) => sum + Int128Syntax.int128AsBigInt(series.quantity).valueOf(), BigInt(0)) >
          BigInt(0)
        );
      }
    });

    if (res) {
      return right(unit);
    } else {
      return left(
        new InsufficientInputFunds(
          transaction.inputs.map(input => input.value),
          transaction.outputs.map(output => output.value)
        )
      );
    }
  }

  /**
   * Asset, Group and Series,  No Repeated Utxos Validation
   * - For all assets minting statement ams1, ams2, ...,  Should not contain repeated UTXOs
   * - For all group/series policies gp1, gp2, ..., ++ sp1, sp2, ..., Should not contain repeated UTXOs
   *
   * @param transaction - transaction
   * @return
   */
  static assetNoRepeatedUtxosValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    const mintingStatementsValidation = Array.from(
      transaction.mintingStatements
        .flatMap(stm => [stm.groupTokenUtxo, stm.seriesTokenUtxo])
        .reduce((acc, utxo) => {
          acc.set(utxo, (acc.get(utxo) || []) as TransactionOutputAddress[]);
          return acc;
        }, new Map<TransactionOutputAddress, TransactionOutputAddress[]>())
        .entries()
    )
      .filter(([address, seqAddresses]) => seqAddresses.length > 1)
      .map(([address]) => new DuplicateInput(address));

    const policiesValidation = Array.from(
      transaction.groupPolicies
        .map(policy => policy.event.registrationUtxo)
        .concat(transaction.seriesPolicies.map(policy => policy.event.registrationUtxo))
        .reduce((acc, utxo) => {
          acc.set(utxo, (acc.get(utxo) || []) as TransactionOutputAddress[]);
          return acc;
        }, new Map<TransactionOutputAddress, TransactionOutputAddress[]>())
        .entries()
    )
      .filter(([address, seqAddresses]) => seqAddresses.length > 1)
      .map(([address]) => new DuplicateInput(address));

    const errors = [...mintingStatementsValidation, ...policiesValidation];

    /// TODO: report all errors?
    return errors.length > 0 ? left(errors[0]) : right(unit);
  }

  private static mintingInputsProjection (transaction: IoTransaction): SpentTransactionOutput[] {
    return transaction.inputs.filter(
      stxo =>
        !(stxo.value.value.case === 'topl') &&
        !(stxo.value.value.case === 'asset') &&
        (!(stxo.value.value.case === 'lvl') ||
          transaction.groupPolicies.some(policy => policy.event.registrationUtxo === stxo.address) ||
          transaction.seriesPolicies.some(policy => policy.event.registrationUtxo === stxo.address))
    );
  }

  private static mintingOutputsProjection (transaction: IoTransaction): UnspentTransactionOutput[] {
    const groupIdsOnMintedStatements = transaction.inputs
      .filter(
        input =>
          input.value.value.case === 'group' &&
          transaction.mintingStatements.some(statement => statement.groupTokenUtxo === input.address)
      )
      .map(input => {
        if (input.value.value.case === 'group') {
          return input.value.value.value.groupId;
        }
      });

    const seriesIdsOnMintedStatements = transaction.inputs
      .filter(
        input =>
          input.value.value.case === 'series' &&
          transaction.mintingStatements.some(statement => statement.seriesTokenUtxo === input.address)
      )
      .map(input => {
        if (input.value.value.case === 'series') {
          return input.value.value.value.seriesId;
        }
      });

    return transaction.outputs.filter(
      utxo =>
        !(utxo.value.value.case === 'lvl') &&
        !(utxo.value.value.case === 'topl') &&
        (!(utxo.value.value.case === 'group') ||
          transaction.groupPolicies.some(policy => {
            if (utxo.value.value.case === 'group') {
              return policy.event.computeId() === utxo.value.value.value.groupId;
            }
          })) &&
        (!(utxo.value.value.case === 'series') ||
          transaction.seriesPolicies.some(policy => {
            if (utxo.value.value.case === 'series') {
              return policy.event.computeId() === utxo.value.value.value.seriesId;
            }
          })) &&
        (!(utxo.value.value.case === 'asset') ||
          (groupIdsOnMintedStatements.includes(utxo.value.value.value.groupId) &&
            seriesIdsOnMintedStatements.includes(utxo.value.value.value.seriesId)))
    );
  }

  static mintingValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    const projectedTransaction = new IoTransaction({
      inputs: this.mintingInputsProjection(transaction),
      outputs: this.mintingOutputsProjection(transaction)
    });

    const groups = projectedTransaction.outputs.flatMap(output => {
      if (output.value.value.case === 'group') {
        return output.value.value.value;
      }
    });
    const series = projectedTransaction.outputs.flatMap(output => {
      if (output.value.value.case === 'series') {
        return output.value.value.value;
      }
    });

    const registrationInPolicyContainsLvls = (registrationUtxo: TransactionOutputAddress): boolean =>
      projectedTransaction.inputs.some(
        stxo =>
          stxo.value.value.case === 'lvl' &&
          stxo.value.value.value.quantity > Int128Syntax.numberAsInt128(0) &&
          stxo.address === registrationUtxo
      );

    const validGroups = groups.every(
      group =>
        transaction.groupPolicies.some(
          policy =>
            policy.event.computeId() === group.groupId &&
            registrationInPolicyContainsLvls(policy.event.registrationUtxo)
        ) && group.quantity > Int128Syntax.numberAsInt128(0)
    );

    const validSeries = series.every(series =>
      transaction.seriesPolicies.some(
        policy =>
          policy.event.computeId() === series.seriesId &&
          registrationInPolicyContainsLvls(policy.event.registrationUtxo) &&
          series.quantity > Int128Syntax.numberAsInt128(0)
      )
    );

    const validAssets = transaction.mintingStatements.every(ams => {
      const maybeSeries = transaction.inputs
        .filter(input => input.value.value.case === 'series' && input.address === ams.seriesTokenUtxo)
        .map(input => {
          if (input.value.value.case === 'series') {
            return input.value.value.value;
          }
        })[0];

      if (maybeSeries) {
        if (maybeSeries.tokenSupply) {
          const sIn = transaction.inputs
            .filter(
              input => input.value.value.case === 'series' && input.value.value.value.seriesId === maybeSeries.seriesId
            )
            .reduce((sum, input) => {
              if (input.value.value.case === 'series') {
                return sum + input.value.value.value.quantity.asbigint();
              }
            }, BigInt(0));

          const sOut = transaction.outputs
            .filter(
              output =>
                output.value.value.case === 'series' && output.value.value.value.seriesId === maybeSeries.seriesId
            )
            .reduce((sum, output) => {
              if (output.value.value.case === 'series') {
                return sum + output.value.value.value.quantity.asbigint();
              }
            }, BigInt(0));

          const burned = sIn - sOut;

          const quantity = transaction.mintingStatements.reduce((sum, ams) => {
            const filterSeries = transaction.inputs
              .filter(input => input.address === ams.seriesTokenUtxo && input.value.value.case === 'series')
              .map(input => {
                if (input.value.value.case === 'series') {
                  return input.value.value.value;
                }
              })
              .filter(series => series.seriesId === maybeSeries.seriesId);

            return sum + (filterSeries.length === 0 ? BigInt(0) : ams.quantity.asbigint());
          }, BigInt(0));

          const amsq = ams.quantity.asbigint();

          return (
            amsq <= maybeSeries.quantity.asbigint() * BigInt(maybeSeries.tokenSupply) &&
            amsq % BigInt(maybeSeries.tokenSupply) === BigInt(0) &&
            burned * BigInt(maybeSeries.tokenSupply) === quantity
          );
        } else {
          return true;
        }
      } else {
        return false;
      }
    });

    if (validGroups && validSeries && validAssets) {
      return right(unit);
    } else {
      return left(
        new InsufficientInputFunds(
          transaction.inputs.map(input => input.value),
          transaction.outputs.map(output => output.value)
        )
      );
    }
  }

  static updateProposalValidation (transaction: IoTransaction): Either<TransactionSyntaxError, Unit> {
    const upsOut = transaction.outputs.flatMap(output => {
      if (output.value.value.case === 'updateProposal') return output.value.value.value;
    });
    const isValid = upsOut.every(up => {
      return (
        up.label.length > 0 &&
        up.fEffective.denominator > Int128Syntax.numberAsInt128(0) &&
        up.fEffective.numerator > Int128Syntax.numberAsInt128(0) &&
        up.vrfLddCutoff > 0 &&
        up.vrfPrecision > 0 &&
        up.vrfBaselineDifficulty.denominator > Int128Syntax.numberAsInt128(0) &&
        up.vrfBaselineDifficulty.numerator > Int128Syntax.numberAsInt128(0) &&
        up.vrfAmplitude.denominator > Int128Syntax.numberAsInt128(0) &&
        up.vrfAmplitude.numerator > Int128Syntax.numberAsInt128(0) &&
        up.chainSelectionKLookback > 0 &&
        up.slotDuration.seconds > 0 &&
        up.forwardBiasedSlotWindow > 0 &&
        up.operationalPeriodsPerEpoch > 0 &&
        up.kesKeyHours > 0 &&
        up.kesKeyMinutes > 0
      );
    });

    return isValid ? right(unit) : left(new InvalidUpdateProposal(upsOut));
  }
}

export class TransactionSyntaxInterpreter extends TransactionSyntaxValidators {
  static validate (t: IoTransaction): Either<TransactionSyntaxError[], IoTransaction> {
    const validators = [
      this.nonEmptyInputsValidation,
      this.distinctInputsValidation,
      this.maximumOutputsCountValidation,
      this.nonNegativeTimestampValidation,
      this.scheduleValidation,
      this.positiveOutputValuesValidation,
      this.sufficientFundsValidation,
      this.attestationValidation,
      this.dataLengthValidation,
      this.assetEqualFundsValidation,
      this.groupEqualFundsValidation,
      this.seriesEqualFundsValidation,
      this.assetNoRepeatedUtxosValidation,
      this.mintingValidation,
      this.updateProposalValidation
    ];

    for (const validator of validators) {
      const result = validator(t);
      if (isLeft(result)) {
        return left([result.left]); // If any validator fails, return the error
      }
    }

    return right(t); // If all validators pass, return the transaction
  }
}
