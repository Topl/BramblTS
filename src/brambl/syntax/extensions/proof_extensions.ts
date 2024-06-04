import {
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
    Proof_TickRange
} from 'topl_common';

/**
 * Extend the Proof interface from 'topl_common' module with additional methods.
 * These methods are marked as optional to not interfere with type identification.
 */
declare module 'topl_common' {
  interface Proof {
    /**
     * Check if the Proof object is empty.
     * @returns A boolean indicating whether the Proof object is empty.
     */
    isEmpty?(): boolean;

    /// --- with methods follow ----

    /**
     * Set the 'locked' value of the Proof.
     * @param value - The Proof_Locked value to set.
     * @returns The Proof with the 'locked' value set.
     */
    withLocked?(value: Proof_Locked): Proof;

    /**
     * Set the 'digest' value of the Proof.
     * @param value - The Proof_Digest value to set.
     * @returns The Proof with the 'digest' value set.
     */
    withDigest?(value: Proof_Digest): Proof;

    /**
     * Set the 'digitalSignature' value of the Proof.
     * @param value - The Proof_DigitalSignature value to set.
     * @returns The Proof with the 'digitalSignature' value set.
     */
    withDigitalSignature?(value: Proof_DigitalSignature): Proof;

    /**
     * Set the 'heightRange' value of the Proof.
     * @param value - The Proof_HeightRange value to set.
     * @returns The Proof with the 'heightRange' value set.
     */
    withHeightRange?(value: Proof_HeightRange): Proof;

    /**
     * Set the 'tickRange' value of the Proof.
     * @param value - The Proof_TickRange value to set.
     * @returns The Proof with the 'tickRange' value set.
     */
    withTickRange?(value: Proof_TickRange): Proof;

    /**
     * Set the 'exactMatch' value of the Proof.
     * @param value - The Proof_ExactMatch value to set.
     * @returns The Proof with the 'exactMatch' value set.
     */
    withExactMatch?(value: Proof_ExactMatch): Proof;

    /**
     * Set the 'lessThan' value of the Proof.
     * @param value - The Proof_LessThan value to set.
     * @returns The Proof with the 'lessThan' value set.
     */
    withLessThan?(value: Proof_LessThan): Proof;

    /**
     * Set the 'greaterThan' value of the Proof.
     * @param value - The Proof_GreaterThan value to set.
     * @returns The Proof with the 'greaterThan' value set.
     */
    withGreaterThan?(value: Proof_GreaterThan): Proof;

    /**
     * Set the 'equalTo' value of the Proof.
     * @param value - The Proof_EqualTo value to set.
     * @returns The Proof with the 'equalTo' value set.
     */
    withEqualTo?(value: Proof_EqualTo): Proof;

    /**
     * Set the 'threshold' value of the Proof.
     * @param value - The Proof_Threshold value to set.
     * @returns The Proof with the 'threshold' value set.
     */
    withThreshold?(value: Proof_Threshold): Proof;

    /**
     * Set the 'not' value of the Proof.
     * @param value - The Proof_Not value to set.
     * @returns The Proof with the 'not' value set.
     */
    withNot?(value: Proof_Not): Proof;

    /**
     * Set the 'and' value of the Proof.
     * @param value - The Proof_And value to set.
     * @returns The Proof with the 'and' value set.
     */
    withAnd?(value: Proof_And): Proof;

    /**
     * Set the 'or' value of the Proof.
     * @param value - The Proof_Or value to set.
     * @returns The Proof with the 'or' value set.
     */
    withOr?(value: Proof_Or): Proof;
  }
}

Proof.prototype.isEmpty = function (): boolean {
  if (this.value === undefined || this.value === null) return true;
  switch (this.value.case) {
    case 'locked':
    case 'digest':
    case 'digitalSignature':
    case 'heightRange':
    case 'tickRange':
    case 'exactMatch':
    case 'lessThan':
    case 'greaterThan':
    case 'equalTo':
    case 'threshold':
    case 'not':
    case 'and':
    case 'or':
      return this.value.value === undefined || this.value.value === null;
    case undefined:
      return true;
    default:
      throw new Error('Unsupported proof type');
  }
};

Proof.prototype.withLocked = function (value: Proof_Locked): Proof {
  this.value = { value, case: 'locked' };
  return this;
};

Proof.prototype.withDigest = function (value: Proof_Digest): Proof {
  this.value = { value, case: 'digest' };
  return this;
};

Proof.prototype.withDigitalSignature = function (value: Proof_DigitalSignature): Proof {
  this.value = { value, case: 'digitalSignature' };
  return this;
};

Proof.prototype.withHeightRange = function (value: Proof_HeightRange): Proof {
  this.value = { value, case: 'heightRange' };
  return this;
};

Proof.prototype.withTickRange = function (value: Proof_TickRange): Proof {
  this.value = { value, case: 'tickRange' };
  return this;
};

Proof.prototype.withExactMatch = function (value: Proof_ExactMatch): Proof {
  this.value = { value, case: 'exactMatch' };
  return this;
};

Proof.prototype.withLessThan = function (value: Proof_LessThan): Proof {
  this.value = { value, case: 'lessThan' };
  return this;
};

Proof.prototype.withGreaterThan = function (value: Proof_GreaterThan): Proof {
  this.value = { value, case: 'greaterThan' };
  return this;
};

Proof.prototype.withEqualTo = function (value: Proof_EqualTo): Proof {
  this.value = { value, case: 'equalTo' };
  return this;
};

Proof.prototype.withThreshold = function (value: Proof_Threshold): Proof {
  this.value = { value, case: 'threshold' };
  return this;
};

Proof.prototype.withNot = function (value: Proof_Not): Proof {
  this.value = { value, case: 'not' };
  return this;
};

Proof.prototype.withAnd = function (value: Proof_And): Proof {
  this.value = { value, case: 'and' };
  return this;
};

Proof.prototype.withOr = function (value: Proof_Or): Proof {
  this.value = { value, case: 'or' };
  return this;
};
