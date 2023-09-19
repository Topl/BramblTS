import * as lock from '../../../proto/brambl/models/box/lock.js';
import * as value from '../../../proto/brambl/models/box/value.js';
import * as challenge from "../../../proto/brambl/models/box/challenge.js";
import * as datum from '../../../proto/brambl/models/datum.js'
import * as event from '../../../proto/brambl/models/event.js';
import * as address from '../../../proto/brambl/models/address.js';
import * as identifier from '../../../proto/brambl/models/identifier.js';
import * as attestation from '../../../proto/brambl/models/transaction/attestation.js';
import * as schedule from '../../../proto/brambl/models/transaction/schedule.js';
import * as unspent_transaction_output from '../../../proto/brambl/models/transaction/unspent_transaction_output.js';
import * as io_transaction from '../../../proto/brambl/models/transaction/io_transaction.js';
import * as txo from '../../../proto/genus/genus_models.js';

//Lock
export class Lock extends lock.co.topl.brambl.models.box.Lock {};
export class Lock_Predicate extends lock.co.topl.brambl.models.box.Lock.Predicate {};

//Value
export class Value extends value.co.topl.brambl.models.box.Value {};

//Identifier
export class Identifier extends identifier.co.topl.brambl.models.Identifier {};

//Datum
export class Datum extends datum.co.topl.brambl.models.Datum {};
export class Datum_IoTransaction extends datum.co.topl.brambl.models.Datum.IoTransaction {};

//Event
export class Event extends event.co.topl.brambl.models.Event {};
export class Event_IoTransaction extends event.co.topl.brambl.models.Event.IoTransaction {};

//Schedule
export class Schedule extends schedule.co.topl.brambl.models.transaction.Schedule {};

//Address
export class Address extends address.co.topl.brambl.models.Address {};

//Attestation
export class Attestation extends attestation.co.topl.brambl.models.transaction.Attestation {};

//Unspent Transaction Output
export class UnspentTransactionOutput extends unspent_transaction_output.co.topl.brambl.models.transaction.UnspentTransactionOutput {};

//IO Transaction
export class IoTransaction extends io_transaction.co.topl.brambl.models.transaction.IoTransaction {};

//TXO
export class Txo extends txo.co.topl.proto.genus.Txo {};


//Challenge
export class Challenge extends challenge.co.topl.brambl.models.box.Challenge {};
