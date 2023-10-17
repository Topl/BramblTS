export interface CipherParameters {
    // Marker interface, does not declare any methods or properties.
  }
  
  export class KeyParameter implements CipherParameters {
    private key: Uint8Array;
  
    constructor(key: Uint8Array) {
      this.key = key;
    }
  
    getKey(): Uint8Array {
      return this.key;
    }
  }
  
  export class ParametersWithIV implements CipherParameters {
    private parameters: CipherParameters;
    private iv: Uint8Array;
  
    constructor(parameters: CipherParameters, iv: Uint8Array) {
      this.parameters = parameters;
      this.iv = iv;
    }
  
    getParameters(): CipherParameters {
      return this.parameters;
    }
  
    getIV(): Uint8Array {
      return this.iv;
    }
  }
  
  export class ParametersWithSBox implements CipherParameters {
    private parameters: CipherParameters;
    private sBox: Uint8Array;
  
    constructor(parameters: CipherParameters, sBox: Uint8Array) {
      this.parameters = parameters;
      this.sBox = sBox;
    }
  
    getParameters(): CipherParameters {
      return this.parameters;
    }
  
    getSBox(): Uint8Array {
      return this.sBox;
    }
  }  