import { Challenge, Proposition, Challenge_PreviousProposition } from 'topl_common';

/**
 * Extend the Challenge interface from 'topl_common' module with additional methods.
 * These methods are marked as optional to not interfere with type identification.
 */
declare module 'topl_common' {
  interface Challenge {
    /**
     * Set the revealed proposition of the challenge.
     * @param proposition - The proposition to set.
     * @returns The challenge with the set proposition.
     */
    withRevealed?(proposition: Proposition): Challenge;

    /**
     * Set the previous proposition of the challenge.
     * @param previous - The previous proposition to set.
     * @returns The challenge with the set previous proposition.
     */
    withPrevious?(previous: Challenge_PreviousProposition): Challenge;
  }
}

Challenge.prototype.withRevealed = function (proposition: Proposition): Challenge {
  this.proposition = { value: proposition, case: 'revealed' };
  return this;
};

Challenge.prototype.withPrevious = function (previous: Challenge_PreviousProposition): Challenge {
  this.proposition = { value: previous, case: 'previous' };
  return this;
};