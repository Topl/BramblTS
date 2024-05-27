import { ValidationError } from '@/quivr4s/quivr/runtime/quivr_runtime_error.js';
import type { Proof, Proposition, Schedule, TransactionOutputAddress, UpdateProposal, Value } from 'topl_common';

export abstract class TransactionSyntaxError extends ValidationError {}

export class EmptyInputs extends TransactionSyntaxError {
  constructor () {
    super(null);
  }
}

export class DuplicateInput extends TransactionSyntaxError {
  knownIdentifier: TransactionOutputAddress;

  constructor (knownIdentifier: TransactionOutputAddress) {
    super(null);
    this.knownIdentifier = knownIdentifier;
  }
}

export class ExcessiveOutputsCount extends TransactionSyntaxError {
  constructor () {
    super(null);
  }
}

export class InvalidTimestamp extends TransactionSyntaxError {
  timestamp: bigint;

  constructor (timestamp: bigint) {
    super(null);
    this.timestamp = timestamp;
  }
}

export class InvalidSchedule extends TransactionSyntaxError {
  schedule: Schedule;

  constructor (schedule: Schedule) {
    super(null);
    this.schedule = schedule;
  }
}

export class NonPositiveOutputValue extends TransactionSyntaxError {
  outputValue: Value;

  constructor (outputValue: Value) {
    super(null);
    this.outputValue = outputValue;
  }
}

export class InsufficientInputFunds extends TransactionSyntaxError {
  inputs: Value[];
  outputs: Value[];

  constructor (inputs: Value[], outputs: Value[]) {
    super(null);
    this.inputs = inputs;
    this.outputs = outputs;
  }
}

export class InvalidProofType extends TransactionSyntaxError {
  proposition: Proposition;
  proof: Proof;

  constructor (proposition: Proposition, proof: Proof) {
    super(null);
    this.proposition = proposition;
    this.proof = proof;
  }
}

export class InvalidDataLength extends TransactionSyntaxError {
  constructor () {
    super(null);
  }
}

export class InvalidUpdateProposal extends TransactionSyntaxError {
  outputs: UpdateProposal[];

  constructor (outputs: UpdateProposal[]) {
    super(null);
    this.outputs = outputs;
  }
}


export class TransactionSyntaxErrors {
  static createEmptyInputs () {
    return new EmptyInputs();
  }

  static createDuplicateInput (knownIdentifier: TransactionOutputAddress) {
    return new DuplicateInput(knownIdentifier);
  }

  static createExcessiveOutputsCount () {
    return new ExcessiveOutputsCount();
  }

  static createInvalidTimestamp (timestamp: bigint) {
    return new InvalidTimestamp(timestamp);
  }

  static createInvalidSchedule (schedule: Schedule) {
    return new InvalidSchedule(schedule);
  }

  static createNonPositiveOutputValue (outputValue: Value) {
    return new NonPositiveOutputValue(outputValue);
  }

  static createInsufficientInputFunds (inputs: Value[], outputs: Value[]) {
    return new InsufficientInputFunds(inputs, outputs);
  }

  static createInvalidProofType (proposition: Proposition, proof: Proof) {
    return new InvalidProofType(proposition, proof);
  }

  static createInvalidDataLength () {
    return new InvalidDataLength();
  }

  static createInvalidUpdateProposal (outputs: UpdateProposal[]) {
    return new InvalidUpdateProposal(outputs);
  }
}