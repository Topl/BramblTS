import { LockTemplate } from '../builders/locks/lock_template.js';
import  {   
    Indices,
    Lock_Predicate,
    KeyPair,
    Preimage,
    Proposition_Digest,
    Proposition_DigitalSignature, } from 'topl_common';

/**
 * Defines a data API for storing and retrieving wallet interaction.
 */

/// new, chose interface because of easier exports
export abstract class WalletStateAlgebra {
  /**
   * Initialize the wallet interaction with the given key pair
   *
   * @param networkId The network id to initialize the wallet interaction with
   * @param ledgerId The ledger id to initialize the wallet interaction with
   * @param mainKey The Topl Main verification key to initialize the wallet interaction with
   */
  abstract initWalletState(networkId: number, ledgerId: number, mainKey: KeyPair): Promise<void>;

  /**
   * Get the indices associated to a signature proposition
   *
   * @param signatureProposition The signature proposition to get the indices for
   * @return The indices associated to the signature proposition if it exists. Else None
   */
  abstract getIndicesBySignature(signatureProposition: Proposition_DigitalSignature): Promise<Indices | null>;

  /**
   * Get the preimage secret associated to a digest proposition.
   *
   * @param digestProposition The Digest Proposition for which to retrieve the preimage secret for
   * @return The preimage secret associated to the Digest Proposition if it exists. Else None
   */
  abstract getPreimage(digestProposition: Proposition_Digest): Promise<Preimage | null>;

  /**
   * Add a preimage secret associated to a digest proposition.
   *
   * @param preimage The preimage secret to add
   * @param digest The digest proposition for which the preimage is derived from.
   */
  abstract addPreimage(preimage: Preimage, digest: Proposition_Digest): Promise<void>;

  /**
   * Get the current address for the wallet interaction
   *
   * @return The current address of the wallet interaction as a string in base58 encoding
   */
  abstract getCurrentAddress(): Promise<string>;

  /**
   * Update the wallet interaction with a new set of Predicate Lock, Lock Address, and their associated Indices
   *
   * @param lockPredicate The lock predicate to add to the wallet interaction
   * @param lockAddress    The lock address to add to the wallet interaction
   * @param routine        The routine to add to the wallet interaction
   * @param vk             The verification key to add to the wallet interaction
   * @param indices        The indices to add to the wallet interaction
   */
  abstract updateWalletState(
    lockPredicate: string,
    lockAddress: string,
    routine: string | null,
    vk: string | null,
    indices: Indices
  ): Promise<void>;

  /**
   * Get the current indices for the given fellowship, template and optional interaction
   *
   * @param fellowship   A String label of the fellowship to get the indices for
   * @param template A String label of the template to get the indices for
   * @param someInteraction The optional interaction index of the indices. If not provided, the next interaction index for the given fellowship
   *                  and template pair will be used
   * @return The indices for the given fellowship, template and optional interaction if possible. Else None
   */
  abstract getCurrentIndicesForFunds(
    fellowship: string,
    template: string,
    someInteraction: number | null
  ): Promise<Indices | null>;

  /**
   * Get the list of interactions for the given fellowship and template.
   *
   * @param fellowship A String label of the fellowship to get the interactions for
   * @param template A String label of the template to get the interactions for
   * @return The list of interactions for the given fellowship and template if possible.
   * If the fellowship or template do not exist it will return None.
   */
  abstract getInteractionList(fellowship: string, template: string): Promise<Array<[Indices, string]> | null>;

  /**
   * Set the current interaction for the given fellowship and template.
   * In practice, this will remove all interactions after the given interaction index
   * from the database, as the current interaction is the latest interaction.
   * The interaction needs to be smaller or equal than the current interaction.
   *
   * @param fellowship  A String label of the fellowship to set the current interaction for
   * @param template A String label of the template to set the current interaction for
   * @param interaction The interaction index to set the current interaction to
   * @return The indices for the given fellowship, template and interaction. If the interaction is not valid, None.
   */
  abstract setCurrentIndices(fellowship: string, template: string, interaction: number): Promise<Indices | null>;

  /**
   * Validate that the supplied fellowship, template and optional interaction exist and are associated with each other in the
   * current wallet interaction
   *
   * @param fellowship   A String label of the fellowship to validate with
   * @param template A String label of the template to validate with
   * @param someInteraction The optional interaction index to validate with. If not provided, the next interaction for the given fellowship
   *                  and template pair will be used
   * @return The indices for the given fellowship, template and optional interaction if valid. If not, the relevant errors
   */
  abstract validateCurrentIndicesForFunds(
    fellowship: string,
    template: string,
    someInteraction: number | null
  ): Promise<Indices | null>; // replace null with the type of ValidatedNel

  /**
   * Get the next available indices for the given fellowship and template
   *
   * @param fellowship   A String label of the fellowship to get the next indices for
   * @param template A String label of the template to get the next indices for
   * @return The next indices for the given fellowship and template if possible. Else None
   */
  abstract getNextIndicesForFunds(fellowship: string, template: string): Promise<Indices | null>;

  /**
   * Get the lock predicate associated to the given indices
   *
   * @param indices The indices to get the lock predicate for
   * @return The lock predicate for the given indices if possible. Else None
   */
  abstract  getLockByIndex(indices: Indices): Promise<Lock_Predicate | null>;

  /**
   * Get the lock predicate associated to the given lockAddress.
   *
   * @param lockAddress The lockAddress for which we are retrieving the lock for
   * @return The lock predicate for the lockAddress if possible. Else None
   */
  abstract getLockByAddress(lockAddress: string): Promise<Lock_Predicate | null>;

  /**
   * Get the lock address associated to the given fellowship, template and optional interaction
   *
   * @param fellowship   A String label of the fellowship to get the lock address for
   * @param template A String label of the template to get the lock address for
   * @param someInteraction The optional interaction index to get the lock address for. If not provided, the next interaction for the
   *                  given fellowship and template pair will be used
   * @return The lock address for the given indices if possible. Else None
   */
  abstract getAddress(fellowship: string, template: string, someInteraction: number | null): Promise<string | null>;

  /**
   * Add a new entry of fellow verification keys to the wallet interaction's cartesian indexing. Entities are at a pair of
   * x (fellowship) and y (template) layers and thus represent a Child verification key at a participants own x/y path.
   * The respective x and y indices of the specified fellowship and template labels must already exist.
   *
   * @param fellowship   A String label of the fellowship to associate the new verification keys with
   * @param template A String label of the template to associate the new verification keys with
   * @param fellows The list of Verification Keys in base58 format to add
   */
  abstract addEntityVks(fellowship: string, template: string, fellows: string[]): Promise<void>;

  /**
   * Get the list of verification keys associated to the given pair of fellowship and template
   *
   * @param fellowship - A String label of the fellowship to get the verification keys for
   * @returns The list of verification keys in base58 format associated to the given fellowship and template if possible.
   *          Else None. It is possible that the list of fellows is empty.
   */
  abstract getEntityVks(fellowship: string, template: string): Promise<string[] | null>;

  /**
   * Add a new lock template entry to the wallet interaction's cartesian indexing. Lock templates are at the y (template)
   * layer. This new entry will be associated to the label given by template. The index of the new entry (and thus
   * associated with the template label) will be automatically derived by the next available y-index.
   *
   * @param template   A String label of the template to associate the new lockTemplate entry with
   * @param lockTemplate The list of Lock Templates of the lock templates to add to the new Entries entry
   */
  abstract addNewLockTemplate(template: string, lockTemplate: LockTemplate): Promise<void>;

  /**
   * Get the lock template associated to the given template
   *
   * @param template - A String label of the template to get the lock template for
   * @returns The lock template associated to the given template if possible. Else None.
   */
  abstract getLockTemplate(template: string): Promise<LockTemplate | null>;

  /**
   * Using the template associated the given template, the verification keys associated to the fellowship and template pair,
   * and the z interaction given by nextInteraction, build a Lock
   *
   * @param fellowship - A String label of the fellowship to get the Lock verification keys for
   * @param template - A String label of the template to get the verification keys and template for
   * @param nextInteraction - The z index interaction to build the lock for
   * @returns A built lock, if possible. Else none
   */
  abstract getLock(fellowship: string, template: string, nextInteraction: number): Promise<Lock | null>;
}
