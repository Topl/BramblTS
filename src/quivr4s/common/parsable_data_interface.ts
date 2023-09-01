import * as data from '../../../proto/quivr/models/shared.js'

/// Provides Digest verification for use in a Dynamic Context
export class ParsableDataInterface {
    data: data.quivr.models.Data;

    constructor(data: data.quivr.models.Data) {
        this.data = data;
    }

    parse(f: (data: data.quivr.models.Data) => T): T {
        return f(this.data);
    }
}
