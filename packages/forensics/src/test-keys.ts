import { generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, createPublicKey } from "node:crypto";
import { b64uEncode } from "./encoding";
import { kidFromPublicKey } from "./keys";
import type { PublicVerificationKey, SigningKey } from "./credentials";

class SigningKeyHandle implements SigningKey {
  constructor(private readonly keyPem: string) {}
  sign(message: Buffer): Buffer {
    return cryptoSign(null, message, this.keyPem);
  }
}

class VerificationKeyHandle implements PublicVerificationKey {
  constructor(readonly kid: string, private readonly pem: string) {}
  verify(message: Buffer, signature: Buffer): boolean {
    try {
      return cryptoVerify(null, message, createPublicKey(this.pem), signature);
    } catch {
      return false;
    }
  }
}

export interface TestKeyPair {
  kid: string;
  privateKey: SigningKey;
  publicKey: PublicVerificationKey;
}

export function generateTestKeyPair(kidOverride?: string): TestKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicDer = b64uEncode(publicKey.export({ type: "spki", format: "der" }));
  const kid = kidOverride ?? kidFromPublicKey(publicDer);
  return {
    kid,
    privateKey: new SigningKeyHandle(privateKey.export({ type: "pkcs8", format: "pem" }) as string),
    publicKey: new VerificationKeyHandle(kid, publicKey.export({ type: "spki", format: "pem" }) as string)
  };
}

export const Ed25519SigningKey = SigningKeyHandle;
export const Ed25519VerificationKey = VerificationKeyHandle;
