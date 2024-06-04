import {
    Datum,
    Datum_Eon,
    Datum_Epoch,
    Datum_Era,
    Datum_GroupPolicy,
    Datum_Header,
    Datum_IoTransaction,
    Datum_SeriesPolicy
} from 'topl_common';


/**
 * Extend the Datum interface from 'topl_common' module with additional methods.
 * These methods are marked as optional to not interfere with type identification.
 */
declare module 'topl_common' {
  interface Datum {
    /**
     * Set the Eon of the Datum.
     * @param eon - The Eon to set.
     * @returns The Datum with the set Eon.
     */
    withEon?(eon: Datum_Eon): Datum;

    /**
     * Set the Era of the Datum.
     * @param era - The Era to set.
     * @returns The Datum with the set Era.
     */
    withEra?(era: Datum_Era): Datum;

    /**
     * Set the Epoch of the Datum.
     * @param epoch - The Epoch to set.
     * @returns The Datum with the set Epoch.
     */
    withEpoch?(epoch: Datum_Epoch): Datum;

    /**
     * Set the Header of the Datum.
     * @param header - The Header to set.
     * @returns The Datum with the set Header.
     */
    withHeader?(header: Datum_Header): Datum;

    /**
     * Set the IoTransaction of the Datum.
     * @param ioTransaction - The IoTransaction to set.
     * @returns The Datum with the set IoTransaction.
     */
    withIoTransaction?(ioTransaction: Datum_IoTransaction): Datum;

    /**
     * Set the GroupPolicy of the Datum.
     * @param groupPolicy - The GroupPolicy to set.
     * @returns The Datum with the set GroupPolicy.
     */
    withGroupPolicy?(groupPolicy: Datum_GroupPolicy): Datum;

    /**
     * Set the SeriesPolicy of the Datum.
     * @param seriesPolicy - The SeriesPolicy to set.
     * @returns The Datum with the set SeriesPolicy.
     */
    withSeriesPolicy?(seriesPolicy: Datum_SeriesPolicy): Datum;
  }
}

Datum.prototype.withEon = function (eon: Datum_Eon): Datum {
  this.value = { value: eon, case: 'eon' };
  return this;
};

Datum.prototype.withEra = function (era: Datum_Era): Datum {
  this.value = { value: era, case: 'era' };
  return this;
};

Datum.prototype.withEpoch = function (epoch: Datum_Epoch): Datum {
  this.value = { value: epoch, case: 'epoch' };
  return this;
};

Datum.prototype.withHeader = function (header: Datum_Header): Datum {
  this.value = { value: header, case: 'header' };
  return this;
};

Datum.prototype.withIoTransaction = function (ioTransaction: Datum_IoTransaction): Datum {
  this.value = { value: ioTransaction, case: 'ioTransaction' };
  return this;
};

Datum.prototype.withGroupPolicy = function (groupPolicy: Datum_GroupPolicy): Datum {
  this.value = { value: groupPolicy, case: 'groupPolicy' };
  return this;
};

Datum.prototype.withSeriesPolicy = function (seriesPolicy: Datum_SeriesPolicy): Datum {
  this.value = { value: seriesPolicy, case: 'seriesPolicy' };
  return this;
};
