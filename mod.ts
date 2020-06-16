/*!
 * Based on https://github.com/crypto-utils/keygrip/blob/master/index.js
 * Copyright(c) 2011-2014 Jed Schmidt
 * Copyright(c) 2020 Christian Norrman
 * MIT Licensed
 */
import { HmacSha256, HmacSha512, base64url } from './deps.ts';

export enum Algorithm {
  SHA256 = 'sha256',
  SHA512 = 'sha512',
}

export class Keygrip {
  #keys: string[];
  #algo: Algorithm;

  constructor(keys: string[], algo: Algorithm=Algorithm.SHA256) {
    if (!keys || !keys.length) {
      throw new Error('Keys must be provided.');
    } else if (algo != 'sha256' && algo != 'sha512') {
      throw new Error('Algorithm not found');
    }

    this.#keys = keys;
    this.#algo = algo;
  }

  sign(data: string, key?: string): string {
    let buffer: ArrayBuffer;
    key = key ?? this.#keys[0];

    if (this.#algo == 'sha256') {
      const hash = new HmacSha256(key);
      buffer = hash.update(data).arrayBuffer();
    } else if (this.#algo == 'sha512') {
      const hash = new HmacSha512(key);
      buffer = hash.update(data).arrayBuffer();
    } else {
      throw new Error('Algorithm invalid');
    }

    return base64url.encode(buffer);
  }

  verify(data: string, digest: string): boolean {
    return this.index(data, digest) != -1;
  }

  index(data: string, digest: string): number {
    return this.#keys.findIndex(key => this.compare(digest, this.sign(data, key)));
  }

  // Timing safe compare using Brad Hill's Double HMAC pattern
  private compare(a: string, b: string): boolean {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const hmac = new HmacSha256(key);
    const ah = hmac.update(a).digest();
    const bh = hmac.update(b).digest();

    return ah.length === bh.length && ah.every((x, i) => x === bh[i]);
  }
}
