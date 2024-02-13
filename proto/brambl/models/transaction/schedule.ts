/**
 * Generated by the protoc-gen-ts.  DO NOT EDIT!
 * compiler version: 3.6.1
 * source: brambl/models/transaction/schedule.proto
 * git: https://github.com/thesayyn/protoc-gen-ts */
import * as pb_1 from "google-protobuf";
export namespace co.topl.brambl.models.transaction {
    export class Schedule extends pb_1.Message {
        #one_of_decls: number[][] = [];
        constructor(data?: any[] | {
            min?: number;
            max?: number;
            timestamp?: number;
        }) {
            super();
            pb_1.Message.initialize(this, Array.isArray(data) ? data : [], 0, -1, [], this.#one_of_decls);
            if (!Array.isArray(data) && typeof data == "object") {
                if ("min" in data && data.min != undefined) {
                    this.min = data.min;
                }
                if ("max" in data && data.max != undefined) {
                    this.max = data.max;
                }
                if ("timestamp" in data && data.timestamp != undefined) {
                    this.timestamp = data.timestamp;
                }
            }
        }
        get min() {
            return pb_1.Message.getFieldWithDefault(this, 1, 0) as number;
        }
        set min(value: number) {
            pb_1.Message.setField(this, 1, value);
        }
        get max() {
            return pb_1.Message.getFieldWithDefault(this, 2, 0) as number;
        }
        set max(value: number) {
            pb_1.Message.setField(this, 2, value);
        }
        get timestamp() {
            return pb_1.Message.getFieldWithDefault(this, 3, 0) as number;
        }
        set timestamp(value: number) {
            pb_1.Message.setField(this, 3, value);
        }
        static fromObject(data: {
            min?: number;
            max?: number;
            timestamp?: number;
        }): Schedule {
            const message = new Schedule({});
            if (data.min != null) {
                message.min = data.min;
            }
            if (data.max != null) {
                message.max = data.max;
            }
            if (data.timestamp != null) {
                message.timestamp = data.timestamp;
            }
            return message;
        }
        toObject() {
            const data: {
                min?: number;
                max?: number;
                timestamp?: number;
            } = {};
            if (this.min != null) {
                data.min = this.min;
            }
            if (this.max != null) {
                data.max = this.max;
            }
            if (this.timestamp != null) {
                data.timestamp = this.timestamp;
            }
            return data;
        }
        serialize(): Uint8Array;
        serialize(w: pb_1.BinaryWriter): void;
        serialize(w?: pb_1.BinaryWriter): Uint8Array | void {
            const writer = w || new pb_1.BinaryWriter();
            if (this.min != 0)
                writer.writeUint64(1, this.min);
            if (this.max != 0)
                writer.writeUint64(2, this.max);
            if (this.timestamp != 0)
                writer.writeUint64(3, this.timestamp);
            if (!w)
                return writer.getResultBuffer();
        }
        static deserialize(bytes: Uint8Array | pb_1.BinaryReader): Schedule {
            const reader = bytes instanceof pb_1.BinaryReader ? bytes : new pb_1.BinaryReader(bytes), message = new Schedule();
            while (reader.nextField()) {
                if (reader.isEndGroup())
                    break;
                switch (reader.getFieldNumber()) {
                    case 1:
                        message.min = reader.readUint64();
                        break;
                    case 2:
                        message.max = reader.readUint64();
                        break;
                    case 3:
                        message.timestamp = reader.readUint64();
                        break;
                    default: reader.skipField();
                }
            }
            return message;
        }
        serializeBinary(): Uint8Array {
            return this.serialize();
        }
        static deserializeBinary(bytes: Uint8Array): Schedule {
            return Schedule.deserialize(bytes);
        }
    }
}
