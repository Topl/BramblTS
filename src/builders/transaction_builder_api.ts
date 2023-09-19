import { Lock, Lock_Predicate, Value, Identifier, Datum, Datum_IoTransaction, Event_IoTransaction, Schedule, Address, Attestation, UnspentTransactionOutput, IoTransaction, Txo } from "./common/types.js";
import { Proof } from "../quivr4s/common/types.js";
import { LockedTemplate } from './locks/proposition_template.js';

abstract class TransactionBuilderApi {
    abstract unprovenAttenstation(lockPredicate: Lock_Predicate): Attestation;
    abstract lockAddress(lock: Lock): Address;
    abstract lvlOutput(predicate: Lock_Predicate, amount: number): UnspentTransactionOutput;
    abstract lvlOutputWithLockAddress(lockAddress: Address, amount: number): UnspentTransactionOutput;
    abstract datum(): Datum_IoTransaction;
    abstract buildSimpleLvlTransaction(lvlTxos: Txo[] , lockPredicateFrom: Lock_Predicate,
        lockPredicateForChange: Lock_Predicate,
        recipientLockAddress: Address,
        amount: number): IoTransaction;
}

class transactionBuilderApiImpl implements TransactionBuilderApi {
    public networkId: number;
    public ledgerId: number;

    constructor(networkId: number, ledgerId: number) {
        this.networkId = networkId;
        this.ledgerId = ledgerId;
    }

    unprovenAttenstation(lockPredicate: Lock_Predicate): Attestation {
        return new Attestation({
            predicate: new Attestation.Predicate({
                lock: lockPredicate,
                responses: new Array(lockPredicate.challenges.length).fill(new Proof())
            })
        });
    };

    lockAddress(lock: Lock): Address {
        return new Address({
            network: this.networkId,
            ledger: this.ledgerId,
            //TODO: Identifier
        });
    };

    lvlOutput(predicate: Lock_Predicate, amount: number): UnspentTransactionOutput {
        return new UnspentTransactionOutput({
            address: new Address({
                network: this.networkId,
                ledger: this.ledgerId,
                //TODO: Identifier
            }),
            //TODO: value
        });
    };

    lvlOutputWithLockAddress(lockAddress: Address, amount: number): UnspentTransactionOutput {
        return new UnspentTransactionOutput({
            address: lockAddress,
            value: new Value({
                lvl: new Value.LVL({
                    quantity: amount
                })
            })
        });
    }

    datum(): Datum_IoTransaction {
        return new Datum_IoTransaction({
            event: new Event_IoTransaction({
                schedule: new Schedule({
                    min: 0,
                    max: Number.MAX_VALUE,
                    //TODO: Long?
                    timestamp: Date.now()
                })
            })
        });
    }

    buildSimpleLvlTransaction(lvlTxos: Txo[] , lockPredicateFrom: Lock_Predicate,
        lockPredicateForChange: Lock_Predicate,
        recipientLockAddress: Address,
        amount: number): IoTransaction {

        }

}

