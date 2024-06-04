import { error } from 'console';
import { IoTransaction, Proof, SpentTransactionOutput, UnspentTransactionOutput } from 'topl_common'; // replace with actual import paths
import { ContainsImmutable } from '../common/contains_immutable.js';
import type TransactionCostCalculator from './algebras/transaction_cost_calculator.js';


export class TransactionCostCalculatorInterpreter implements TransactionCostCalculator {
  private transactionCostConfig: TransactionCostConfig;
  private proofCostConfig: ProofCostConfig;

  constructor () {
    this.proofCostConfig = new ProofCostConfig();
    this.transactionCostConfig = new TransactionCostConfig({ proofCostConfig: this.proofCostConfig });
  }

  costOf (transaction: IoTransaction): number {
    const t = this.transactionCostConfig;

    return (
      t.baseCost +
      this.transactionDataCost(transaction) +
      transaction.inputs.map(this.transactionInputCost).bSum() +
      transaction.outputs.map(this.transactionOutputCost).bSum()
    );
  }

  /**
   * A Transaction consumes disk space and network bandwidth.  The bigger the transaction, the more it
   * costs to save and transmit.
   *
   * @param transaction the transaction to cost
   * @returns a cost, represented as a number
   */
  private transactionDataCost (transaction: IoTransaction): number {
    const bytes = ContainsImmutable.ioTransaction(transaction).immutableBytes.value;
    return (bytes.length * this.transactionCostConfig.dataCostPerMB) / 1024 / 1024;
  }

  /**
   * Calculates the cost of consuming a UTxO. Consuming a UTxO clears up some space in the UTxO set (a good thing), but
   * verifying the Proof that consumes the UTxO costs some resources.
   *
   * @param input The input to cost
   * @returns a cost, represented as a number
   */
  private transactionInputCost (input: SpentTransactionOutput): number {
    var cost = this.transactionCostConfig.inputCost;

    switch (input.attestation.value.case) {
      case 'predicate':
        cost += input.attestation.value.value.responses.map(this.proofCost).bSum();
        break;
      case 'image':
        cost += input.attestation.value.value.responses.map(this.proofCost).bSum();
        break;
      case 'commitment':
        cost += input.attestation.value.value.responses.map(this.proofCost).bSum();
        break;
      default:
        throw error('Unknown attestation type');
    }

    return cost;
  }

  /**
   * Proof verification has a CPU/memory cost associated with it.  Different proofs have different complexity.
   *
   * @param proof the proof to cost
   * @returns a cost, represented as a number
   */
  private proofCost (proof: Proof): number {
    const c = this.proofCostConfig;
    if (proof.value === null) return c.emptyCost;
    switch (proof.value.case) {
      case 'locked':
        return c.lockedCost;
      case 'digest':
        return c.txBindCost + c.digestCost;
      case 'digitalSignature':
        return c.txBindCost + c.digitalSignatureCost;
      case 'heightRange':
        return c.txBindCost + c.heightRangeCost;
      case 'tickRange':
        return c.txBindCost + c.tickRangeCost;
      case 'exactMatch':
        return c.txBindCost + c.exactMatchCost;
      case 'lessThan':
        return c.txBindCost + c.lessThanCost;
      case 'greaterThan':
        return c.txBindCost + c.greaterThanCost;
      case 'equalTo':
        return c.txBindCost + c.equalToCost;
      case 'threshold':
        return c.txBindCost + c.thresholdCost + proof.value.value.responses.map(this.proofCost).bSum();
      case 'not':
        return c.txBindCost + c.notCost + this.proofCost(proof);
      case 'and':
        return (
          c.txBindCost + c.andCost + this.proofCost(proof.value.value.left) + this.proofCost(proof.value.value.right)
        );
      case 'or':
        return (
          c.txBindCost + c.orCost + this.proofCost(proof.value.value.left) + this.proofCost(proof.value.value.right)
        );
      default:
        throw new Error('Unknown proof type');
    }
  }

  private transactionOutputCost (output: UnspentTransactionOutput): number {
    return this.transactionCostConfig.outputCost;
  }
}

export class TransactionCostConfig {
  baseCost: number;
  dataCostPerMB: number;
  inputCost: number;
  outputCost: number;
  proofCostConfig: ProofCostConfig;

  /**
   * Configuration values for individual cost components
   * @param baseCost a base value to pad to the transaction cost
   * @param dataCostPerMB cost per megabyte of data of the transaction's immutable bytes
   * @param inputCost base cost per each consumed input (consuming an input is a good thing) (proof costs are added on)
   * @param outputCost base cost for each new output
   * @param proofCostConfig configuration values for individual proofs
   */
  constructor ({ baseCost = 1, dataCostPerMB = 1024, inputCost = -1, outputCost = 5, proofCostConfig }) {
    this.baseCost = baseCost;
    this.dataCostPerMB = dataCostPerMB;
    this.inputCost = inputCost;
    this.outputCost = outputCost;
    this.proofCostConfig = proofCostConfig;
  }
}

/// Configuration values for individual proof cost components.
export class ProofCostConfig {
  txBindCost: number;
  emptyCost: number;
  lockedCost: number;
  digestCost: number;
  digitalSignatureCost: number;
  heightRangeCost: number;
  tickRangeCost: number;
  exactMatchCost: number;
  lessThanCost: number;
  greaterThanCost: number;
  equalToCost: number;
  thresholdCost: number;
  andCost: number;
  orCost: number;
  notCost: number;

  /**
   * Configuration values for individual proof cost components.
   * @param txBindCost The cost to verify a TxBind (hash verification)
   * @param emptyCost The cost to verify an empty proof
   * @param lockedCost The cost to verify a locked proof
   * @param digestCost The cost to verify a digest/hash
   * @param digitalSignatureCost The cost to verify a digital signature (likely EC)
   * @param heightRangeCost The cost to verify a height range (probably cheap, statically provided value)
   * @param tickRangeCost The cost to verify a tick range (probably cheap, statically provided value)
   * @param exactMatchCost The cost to verify an exact match (probably cheap, lookup function)
   * @param lessThanCost The cost to verify a less than (probably cheap, lookup function)
   * @param greaterThanCost The cost to verify a greater than (probably cheap, lookup function)
   * @param equalToCost The cost to verify an equal to (probably cheap, lookup function)
   * @param thresholdCost The base cost to verify a threshold (recursive calls will be added)
   * @param andCost The base cost to verify an and (recursive calls will be added)
   * @param orCost The base cost to verify an or (recursive calls will be added)
   * @param notCost The base cost to verify a not (recursive call will be added)
   */
  constructor ({
    txBindCost = 50,
    emptyCost = 1,
    lockedCost = 1,
    digestCost = 50,
    digitalSignatureCost = 100,
    heightRangeCost = 5,
    tickRangeCost = 5,
    exactMatchCost = 10,
    lessThanCost = 10,
    greaterThanCost = 10,
    equalToCost = 10,
    thresholdCost = 1,
    andCost = 1,
    orCost = 1,
    notCost = 1
  }: Partial<ProofCostConfig> = {}) {
    this.txBindCost = txBindCost;
    this.emptyCost = emptyCost;
    this.lockedCost = lockedCost;
    this.digestCost = digestCost;
    this.digitalSignatureCost = digitalSignatureCost;
    this.heightRangeCost = heightRangeCost;
    this.tickRangeCost = tickRangeCost;
    this.exactMatchCost = exactMatchCost;
    this.lessThanCost = lessThanCost;
    this.greaterThanCost = greaterThanCost;
    this.equalToCost = equalToCost;
    this.thresholdCost = thresholdCost;
    this.andCost = andCost;
    this.orCost = orCost;
    this.notCost = notCost;
  }
}
