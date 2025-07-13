import { KeyPair, ready, crypto_auth_hmacsha256 as HMAC, from_string, crypto_kx_client_session_keys, crypto_kx_server_session_keys} from 'libsodium-wrappers-sumo';
import { Bytes, PublicKey, ChainKey } from './types';

export type RootKey = Uint8Array;

export enum Side {
    Client = 0,
    Server = 1
}

export async function deriveHKDFKey(
    inputKeyMaterial: Bytes, 
    length: number, 
    salt?: Bytes, 
    info?: string
): Promise<Bytes> {
    await ready;

    const extractedKey = await hkdfExtract(salt, inputKeyMaterial);
    const expandedKey = await hkdfExpand(extractedKey, length, info);
    
    return expandedKey;
}

function hkdfExtract(salt: Bytes | undefined, inputKeyMaterial: Bytes): Bytes {
    const actualSalt = salt || new Uint8Array(32).fill(0);
    return HMAC(inputKeyMaterial, actualSalt);
}

async function hkdfExpand(pseudoRandomKey: Bytes, length: number, info?: string): Promise<Bytes> {
    const hashLength = 32; 
    const n = Math.ceil(length / hashLength);
    
    if (n > 255) {
        throw new Error('HKDF: length too large');
    }
    
    const infoBytes = info ? from_string(info) : new Uint8Array(0);
    const output = new Uint8Array(length);
    let previousT = new Uint8Array(0);
    
    for (let i = 1; i <= n; i++) {
        const input = new Uint8Array(previousT.length + infoBytes.length + 1);
        input.set(previousT, 0);
        input.set(infoBytes, previousT.length);
        input.set([i], previousT.length + infoBytes.length);
        
        const t = HMAC(input, pseudoRandomKey);
        
        const startIndex = (i - 1) * hashLength;
        const endIndex = Math.min(startIndex + hashLength, length);
        const copyLength = endIndex - startIndex;
        
        output.set(t.slice(0, copyLength), startIndex);
        previousT = t;
    }
    
    return output;
}

export class RootChain {
    keyPair: KeyPair;
    remotePublicKey: PublicKey | undefined;
    rootKey: RootKey;
    readonly info: string;

    constructor(info: string, rootKey: RootKey, keyPair: KeyPair, remotePublicKey?: PublicKey) {
        this.info = info;
        this.rootKey = rootKey;
        this.keyPair = keyPair;
        this.remotePublicKey = remotePublicKey;
    }

    async ratchetStep(side: Side): Promise<ChainKey> {
        if (!this.remotePublicKey) {
            throw Error("Remote public key is missing. Cant do ratchet.");
        }

        const dhResult = await this.dh(this.keyPair, this.remotePublicKey, side);
        const { rootKey, chainKey } = await this.deriveFromRootKDF(this.rootKey, dhResult, this.info);
        this.rootKey = rootKey;
        return chainKey;
    }

    async dh(
        keyPair: KeyPair,
        theirPublicKey: PublicKey,
        side: Side
      ): Promise<Bytes> {
        await ready;
      
        if (side === Side.Client) { 
          const { sharedTx } = crypto_kx_client_session_keys(
            keyPair.publicKey,  
            keyPair.privateKey,  
            theirPublicKey     
          );
          return sharedTx;
        } else { 
          const { sharedRx } = crypto_kx_server_session_keys(
            keyPair.publicKey,
            keyPair.privateKey,
            theirPublicKey
          );
          return sharedRx;
        }
      }
    async deriveFromRootKDF(rootKey: Bytes, dhOut: Bytes, info: string): Promise<{ rootKey: Bytes, chainKey: Bytes }> {
        const derivedKey = await deriveHKDFKey(dhOut, 64, rootKey, info);
        return {
            rootKey: derivedKey.slice(0, 32), 
            chainKey: derivedKey.slice(32, 64)
        };
    }
}