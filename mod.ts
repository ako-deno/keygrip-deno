/*!
 * keygrip
 * Copyright(c) 2011-2014 Jed Schmidt
 * Copyright(c) 2020 Christian Norrman
 * MIT Licensed
 */

import { HmacSha256, HmacSha512 } from './deps.ts';

const SANITIZE_REGEXP = /\/|\+|=/g;
const SANITIZE_REPLACERS = {
  "/": "_",
  "+": "-",
  "=": "",
} as Record<string, string>;

export enum Algorithm {
  SHA256 = 'sha256',
  SHA512 = 'sha512',
}

export class Keygrip {
  #keys: string[];
  #decoder: TextDecoder;
  #algo: Algorithm;

  constructor(keys: string[], algo: Algorithm=Algorithm.SHA256, enc: string='base64') {
    if (!keys || !keys.length) {
      throw new Error('Keys must be provided.');
    } else if (algo != 'sha256' && algo != 'sha512') {
      throw new Error('Algorithm not found');
    }

    this.#keys = keys;
    this.#algo = algo;
    this.#decoder = new TextDecoder(enc);
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
      // Required for typescript
      throw new Error('Algorithm invalid');
    }

    return this.#decoder
      .decode(buffer)
      .replace(SANITIZE_REGEXP, s => SANITIZE_REPLACERS[s]);
  }

  verify(data: string, digest: string): boolean {
    return this.index(data, digest) != -1;
  }

  index(data: string, digest: string): number {
    return this.#keys.findIndex(key => digest === this.sign(data, key));
  }
}
