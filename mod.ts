/*!
 * Based on https://github.com/crypto-utils/keygrip/blob/master/index.js
 * Copyright(c) 2011-2014 Jed Schmidt
 * Copyright(c) 2020 Christian Norrman
 * MIT Licensed
 */
import { base64url, HmacSha256, HmacSha512 } from "./deps.ts";

/**
 * Enum of supported algorithms for keygrip
 * @enum
 */
export enum Algorithm {
  SHA256 = "sha256",
  SHA512 = "sha512",
}

/**
 * Creates a class for storing private keys in a keychain to easily hash and verify data with different keys
 * @class
 */
export class Keygrip {
  readonly #keys: string[];
  readonly #algo: Algorithm;

  /**
   * @param {string[]} keys
   * @param {Algorithm} [algo='sha256']
   */
  constructor(keys: string[], algo: Algorithm = Algorithm.SHA256) {
    if (!keys || !keys.length) {
      throw new TypeError("Keys must be provided.");
    } else if (algo != Algorithm.SHA256 && algo != Algorithm.SHA512) {
      throw new TypeError("Invalid algorithm");
    }

    this.#keys = keys;
    this.#algo = algo;
  }

  /**
   * Cryptographically sign data by a secret key
   * @param {string} data Data to sign
   * @param {string|number} [key] If key is a number it resolves the key as an index in the keychain.
   *    If it is a string it is used directly. Defaults to first key in the keychain.
   *
   * @returns {string}
   */
  sign(data: string, key?: string | number): string {
    const secret = (typeof key == "number" ? this.#keys[key] : key) ??
      this.#keys[0];
    let buf: ArrayBuffer;

    switch (this.#algo) {
      case Algorithm.SHA256:
        buf = new HmacSha256(secret).update(data).arrayBuffer();
        break;

      case Algorithm.SHA512:
        buf = new HmacSha512(secret).update(data).arrayBuffer();
        break;
    }

    return base64url.encode(new Uint8Array(buf));
  }

  /**
   * Verifies if the data matches the digest with any of the keys in the keychain.
   * @param {string} data Data to digest and verify
   * @param {string} digest Digested hash to compare against
   *
   * @returns {boolean}
   */
  verify(data: string, digest: string): boolean {
    return this.index(data, digest) != -1;
  }

  /**
   * Resolve the index of which key was used to digest specified data.
   * @param {string} data Data to digest
   * @param {string} digest Digested hash to compare against
   *
   * @returns {number}
   */
  index(data: string, digest: string): number {
    return this.#keys.findIndex((key) =>
      this.compare(digest, this.sign(data, key))
    );
  }

  /**
   * Timing safe compare using Brad Hill's Double HMAC pattern
   * @param {string} a Digested data a
   * @param {string} b Digested data b
   *
   * @returns {boolean}
   * @private
   */
  private compare(a: string, b: string): boolean {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const ah = new HmacSha256(key).update(a).digest();
    const bh = new HmacSha256(key).update(b).digest();

    return ah.length === bh.length && ah.every((x, i) => x === bh[i]);
  }
}
