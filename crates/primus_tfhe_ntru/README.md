# primus_tfhe_ntru

English | [简体中文](README.zh_CN.md)

Backend-independent NTRU-TFHE parameters and LWE clients. Transform-domain server
keys and evaluators belong to [NTT](../primus_tfhe_ntru_ntt/README.md) or
[Fourier](../primus_tfhe_ntru_fourier/README.md).
See the [shared capability and encoding guide](../primus_tfhe/README.md).

## Parameters and key domains

`NtruTfheParameters::try_new(external_lwe, bootstrapping, key_switching)` binds the
external LWE to a binary prefix of `f_client`; the rest of that NTRU secret is zero.
`bootstrapping` describes the accumulator under `f_acc`, and `key_switching`
describes the return to `f_client`. Ring lengths, plaintext moduli and ciphertext moduli must match, with
`1 <= external_lwe.dimension() <= N`. Construction also prepares ordinary-PBS
quantization and requires `log2(2N) <= T::BITS`.

Ordinary PBS follows one fixed chain: BR under `f_acc` → NTRU key switch to
`f_client` → compact LWE extraction. There is no order option. Allocate external
outputs using `external_lwe().dimension()`; use paired context/client/server keys.

## Clients and LUTs

Client encryption takes `T`, and decryption returns `Result<T, NtruClientError>`
with a canonical residue in `[0,t)`; applications handle message type conversions.

Contexts expose `encryptor` and `decryptor`; direct construction uses
`NtruEncryptor::try_new` and `NtruDecryptor::try_new`. Encryption accepts the client
key or `LwePublicKey` from `client_key.try_generate_public_key(parameters, rng)`.
This is an external LWE public key under the binary prefix, not an NTRU ring public key.
Decryption requires the client key. See [LWE public-key noise and identity requirements](../primus_lwe/README.md#public-key-encryption).

`encrypt`, `encrypt_padded` and `encrypt_centered` each provide
`*_to(message, output, rng)`. Both key types reuse output storage and reject message
or dimension errors before sampling/writing. Use padded unsigned input with ordinary
family/context LUTs; centered modular messages have a separate encoding contract.

ManyLUT compiles several functions of one input. The backend message/carry example
splits an input into `x % 4` and `x / 4`; it does not implement a complete encrypted
integer type or arithmetic system.

## CBS and examples

Both backends provide optional CBS parameters, keys and evaluators. CBS branches
after BR, projects coefficients and applies trace/scheme switching under `f_acc`;
it skips ordinary PBS's return key switch and extraction. Its NGSW output uses
gadget scales and can control CMUX for `0/1` inputs. CMUX candidates must also use
`f_acc`. NTRU Boolean adapters and packing are not provided by this TFHE layer.

Backend READMEs link runnable PBS and CBS → CMUX examples. Fixtures do not establish
production noise margins or security; NTRU scheme switching requires separate
secret-dependent-message assumptions described in the [NTRU contracts](../primus_ntru/README.md).

## Validation

```sh
cargo test -p primus_tfhe_ntru
cargo doc -p primus_tfhe_ntru --no-deps
```
