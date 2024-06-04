import {
    Attestation,
    Attestation_Commitment,
    Attestation_Image,
    Attestation_Predicate
} from 'topl_common';

/**
 * Extend the Attestation interface from 'topl_common' module with additional methods.
 * These methods are marked as optional to not interfere with type identification.
 */
declare module 'topl_common' {
  interface Attestation {
    /**
     * Set the predicate of the attestation.
     * @param predicate - The predicate to set.
     * @returns The attestation with the set predicate.
     */
    withPredicate?(predicate: Attestation_Predicate): Attestation;

    /**
     * Set the image of the attestation.
     * @param image - The image to set.
     * @returns The attestation with the set image.
     */
    withImage?(image: Attestation_Image): Attestation;

    /**
     * Set the commitment of the attestation.
     * @param commitment - The commitment to set.
     * @returns The attestation with the set commitment.
     */
    withCommitment?(commitment: Attestation_Commitment): Attestation;
  }
}

Attestation.prototype.withPredicate = function (predicate: Attestation_Predicate): Attestation {
  this.value = { value: predicate, case: 'predicate' };
  return this;
};

Attestation.prototype.withImage = function (image: Attestation_Image): Attestation {
  this.value = { value: image, case: 'image' };
  return this;
};

Attestation.prototype.withCommitment = function (commitment: Attestation_Commitment): Attestation {
  this.value = { value: commitment, case: 'commitment' };
  return this;
};
