import {SIGHASH_ALL, SIGHASH_FORKID} from '@relayx/crypto/lib/bitcoin/sighash'
import { serialize } from '@relayx/crypto/lib/bitcoin/script';
import BufferWriter from '@relayx/crypto/lib/bitcoin/BufferWriter';
import { KeyStorage } from "@relayx/wallet/lib/auth";
import {get, set, clear} from './storage'
import { getKeys } from "./crypto";
import { getPublicKey, sign, etc, ProjectivePoint } from '@noble/secp256k1'
import { toDer } from "./bitcoin/signature";
import {signMessage} from './crypto'
import { encrypt , decrypt} from "./ecies";

const keys: KeyStorage = {
  async hasKeys(): Promise<boolean> {
    return !!(await this.getEntropy())
  },
  async getEntropy(): Promise<string> {
    return get<string>('ENTROPY')
  },
  async auth(
    paymail: string,
    entropy: string
  ): Promise<boolean> {
    await set({ 'ENTROPY': entropy, 'PAYMAIL': paymail })
    return true
  },
  async logout(): Promise<boolean> {
    await clear()
    return true
  },
  async getIdentity(): Promise<{
    pubkey: Buffer;
    paymail: string;
  }> {
    const keys = getKeys(await this.getEntropy())
    return {
      pubkey: Buffer.from(getPublicKey( (await keys).identity)),
      paymail: (await get<string>('PAYMAIL'))
    }
  },
  async getRunAddress(): Promise<string> {
    const keys = await getKeys(await this.getEntropy())
    return keys.runAddress
  },
  async getNextChange(): Promise<[string, number]> {
    const keys = await getKeys(await this.getEntropy())
    return [keys.changeAddress, 0]
  },
  async getNextAddress(): Promise<string> {
    const keys = await getKeys(await this.getEntropy())
    return keys.receiveAddress
  },
  async getNextBatonAddress(): Promise<string> {
    const keys = await getKeys(await this.getEntropy())
    return keys.batonAddress
  },
  async isRecentOwnChangeAddress(address: string): Promise<false | number> {
    const keys = await getKeys(await this.getEntropy())
    return address === keys.changeAddress ? 0 : false
  },
  async sign(sighash: Buffer, chain: number, index: number): Promise<Buffer> {
    const keys = await getKeys(await this.getEntropy());
    let privateKey: bigint;
    if (chain === 0) {
      privateKey = keys.receive
    } else if (chain === -1) {
      throw new Error('Contact relayx')
    } else if (chain === -2) {
      throw new Error('Contact relayx')
    } else if (chain === -3) {
      privateKey = keys.run
    } else if (chain === -4) {
      privateKey = keys.baton
    } else {
      privateKey = keys.change
    }
    const pubkey = getPublicKey(privateKey) ;

    const { r, s } = sign(sighash.toString('hex'), etc.numberToBytesBE(privateKey));

    return serialize([
      Buffer.concat([
        toDer(r, s),
        new BufferWriter().writeUInt8(SIGHASH_ALL | SIGHASH_FORKID).concat()
      ]),
      Buffer.from(pubkey)
    ]);
  },
  async signMessage(message: Buffer, pubkey: Buffer): Promise<string> {
    const keys = await getKeys(await this.getEntropy())
    return signMessage(message, keys.identity)
  },
  async encrypt(message: Buffer, pubkey: Buffer, targetPubkey: Buffer): Promise<Buffer> {
    const keys = await getKeys(await this.getEntropy())
    const targetPub = ProjectivePoint.fromHex(targetPubkey)

    return encrypt(keys.identity, targetPub, message)
  },
  async decrypt(message: Buffer, pubkey: Buffer): Promise<Buffer> {
    const keys = await getKeys(await this.getEntropy())

    return decrypt(keys.identity, message)

  }
}

export default keys
