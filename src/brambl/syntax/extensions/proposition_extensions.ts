import {
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
} from 'topl_common';

declare module 'topl_common' {
  interface Proposition {
    /**
     * Checks if the proposition is empty.
     * @returns {boolean} - Returns true if the proposition is empty, false otherwise.
     */
    isEmpty?(): boolean;

    /**
     * Sets the 'locked' case of the proposition with the provided value.
     * @param {Proposition_Locked} value - The value to set.
     * @returns {Proposition} - The proposition instance.
     */
    withLocked?(value: Proposition_Locked): Proposition;

    /**
     * Sets the 'digest' case of the proposition with the provided value.
     * @param {Proposition_Digest} value - The value to set.
     * @returns {Proposition} - The proposition instance.
     */
    withDigest?(value: Proposition_Digest): Proposition;

    /**
     * Sets the 'digitalSignature' case of the proposition with the provided value.
     * @param {Proposition_DigitalSignature} value - The value to set.
     * @returns {Proposition} - The proposition instance.
     */
    withDigitalSignature?(value: Proposition_DigitalSignature): Proposition;

    /**
     * Sets the 'heightRange' case of the proposition with the provided value.
     * @param {Proposition_HeightRange} value - The value to set.
     * @returns {Proposition} - The proposition instance.
     */
    withHeightRange?(value: Proposition_HeightRange): Proposition;

    /**
     * Sets the 'tickRange' case of the proposition with the provided value.
     * @param {Proposition_TickRange} value - The value to set.
     * @returns {Proposition} - The proposition instance.
     */
    withTickRange?(value: Proposition_TickRange): Proposition;

    /**
     * Sets the 'exactMatch' case of the proposition with the provided value.
     * @param {Proposition_ExactMatch} value - The value to set.
     * @returns {Proposition} - The proposition instance.
     */
    withExactMatch?(value: Proposition_ExactMatch): Proposition;

    /**
     * Sets the 'lessThan' case of the proposition with the provided value.
     * @param {Proposition_LessThan} value - The value to set.
     * @returns {Proposition} - The proposition instance.
     */
    withLessThan?(value: Proposition_LessThan): Proposition;

    /**
     * Sets the 'greaterThan' case of the proposition with the provided value.
     * @param {Proposition_GreaterThan} value - The value to set.
     * @returns {Proposition} - The proposition instance.
     */
    withGreaterThan?(value: Proposition_GreaterThan): Proposition;

    /**
     * Sets the 'equalTo' case of the proposition with the provided value.
     * @param {Proposition_EqualTo} value - The value to set.
     * @returns {Proposition} - The proposition instance.
     */
    withEqualTo?(value: Proposition_EqualTo): Proposition;

    /**
     * Sets the 'threshold' case of the proposition with the provided value.
     * @param {Proposition_Threshold} value - The value to set.
     * @returns {Proposition} - The proposition instance.
     */
    withThreshold?(value: Proposition_Threshold): Proposition;

    /**
     * Sets the 'not' case of the proposition with the provided value.
     * @param {Proposition_Not} value - The value to set.
     * @returns {Proposition} - The proposition instance.
     */
    withNot?(value: Proposition_Not): Proposition;

    /**
     * Sets the 'and' case of the proposition with the provided value.
     * @param {Proposition_And} value - The value to set.
     * @returns {Proposition} - The proposition instance.
     */
    withAnd?(value: Proposition_And): Proposition;

    /**
     * Sets the 'or' case of the proposition with the provided value.
     * @param {Proposition_Or} value - The value to set.
     * @returns {Proposition} - The proposition instance.
     */
    withOr?(value: Proposition_Or): Proposition;
  }
}

Proposition.prototype.isEmpty = function (): boolean {
  const prop = this as Proposition;

  if (prop.value === undefined || prop.value === null) {
    return true;
  }

  switch (prop.value.case) {
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
      return prop.value.value === undefined || prop.value.value === null;
    case undefined:
      return true;
    default:
      throw new Error('Unsupported proposition type');
  }
};

Proposition.prototype.withLocked = function (value: Proposition_Locked): Proposition {
  this.value = { value, case: 'locked' };
  return this;
};

Proposition.prototype.withDigest = function (value: Proposition_Digest): Proposition {
  this.value = { value, case: 'digest' };
  return this;
};

Proposition.prototype.withDigitalSignature = function (value: Proposition_DigitalSignature): Proposition {
  this.value = { value, case: 'digitalSignature' };
  return this;
};

Proposition.prototype.withHeightRange = function (value: Proposition_HeightRange): Proposition {
  this.value = { value, case: 'heightRange' };
  return this;
};

Proposition.prototype.withTickRange = function (value: Proposition_TickRange): Proposition {
  this.value = { value, case: 'tickRange' };
  return this;
};

Proposition.prototype.withExactMatch = function (value: Proposition_ExactMatch): Proposition {
  this.value = { value, case: 'exactMatch' };
  return this;
};

Proposition.prototype.withLessThan = function (value: Proposition_LessThan): Proposition {
  this.value = { value, case: 'lessThan' };
  return this;
};

Proposition.prototype.withGreaterThan = function (value: Proposition_GreaterThan): Proposition {
  this.value = { value, case: 'greaterThan' };
  return this;
};

Proposition.prototype.withEqualTo = function (value: Proposition_EqualTo): Proposition {
  this.value = { value, case: 'equalTo' };
  return this;
};

Proposition.prototype.withThreshold = function (value: Proposition_Threshold): Proposition {
  this.value = { value, case: 'threshold' };
  return this;
};

Proposition.prototype.withNot = function (value: Proposition_Not): Proposition {
  this.value = { value, case: 'not' };
  return this;
};

Proposition.prototype.withAnd = function (value: Proposition_And): Proposition {
  this.value = { value, case: 'and' };
  return this;
};

Proposition.prototype.withOr = function (value: Proposition_Or): Proposition {
  this.value = { value, case: 'or' };
  return this;
};
