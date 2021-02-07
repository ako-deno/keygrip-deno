# keygrip

A verification mechanism using multiple different keys stored in a keychain to
cryptographically sign data using SHA256 or SHA512 with HMAC. Code based on
`https://github.com/crypto-utils/keygrip`.

## API

```js
import { Algorithm, Keygrip } from "https://deno.land/x/keygrip/mod.ts";
```

### [keygrip = new Keygrip( keys [, algo=Algorithm.SHA256] )](#keygrip)

Creates a class for storing private keys in a keychain to easily hash and verify
data with multiple different keys.

**Returns:** A new instance of the keygrip class

#### Parameters

- `keys {string[]}` -
- `algo {Algorithm}` -

### [keygrip.sign( data [, key] )](#sign)

Cryptographically sign data by a secret key

**Returns:** a string with the signed hash of the data.

#### Parameters

- `data {string}` - Data to sign
- `key {string|number}` - If key is a number it resolves the key as an index in
  the keychain. If it is a string it is used directly. Defaults to first key in
  the keychain.

### [keygrip.verify( data, digest )](#verify)

Verifies if the data matches the digest with any of the keys in the keychain.

**Returns:** A boolean if any key in the chain could be used to achieve the same
digest.

#### Parameters

- `data {string}` - Data to digest and verify
- `digest {string}` - Digested hash to compare against

### [keygrip.index( data, digest )](#index)

Resolve the index of which key was used to digest specified data.

**Returns:** A number from -1 to the last index of the keychain

#### Parameters

- `data {string}` - Data to digest
- `digest {string}` - Digested hash to compare against

## Examples

```js
import { Algorithm, Keygrip } from "https://deno.land/x/keygrip/mod.ts";

// Uses sha256 by default, could be changed to sha512 with second parameter
const keygrip = new Keygrip(["shh", "secret", "keys"]);

// Sign data with default key
const hash = keygrip.sign("some_important_data");

// Verify the data using the hash
keygrip.verify("some_important_data", hash);
// returns true

// Get index of key in keygrip
keygrip.index("some_important_data", hash);
// returns 0, for key at index 0 in the Keygrip keychain
```

## Testing

```sh
$ deno test
```

## License

[MIT](./LICENSE)
