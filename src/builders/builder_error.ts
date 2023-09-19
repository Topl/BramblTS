//TODO: Upgrade typescript to include cause

export class BuilderError extends Error {
    public message: string;

    constructor(message: string) {
        super();
        this.message = message;
    }
};