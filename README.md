# PKA Peripheral Driver

This module provides an abstraction layer for the **public key accelerator** (`PKA`) of STM32 MCUs: the big-number arithmetic
over the prime fields and the operations built on it - the **RSA** modular exponentiation (also with the Chinese remainder
theorem), the **elliptic curve** point operations and the **ECDSA** signature generation and verification. It takes the
operands as ordinary big-endian byte arrays, runs the operation in the accelerator and returns the result. It is a
low-level MCAL module: it owns the PKA hardware and its RAM, the application and the other modules never touch the
registers.

The public interface (`Pka_Port.h`, `Pka_Types.h`) is **identical for all supported families**. The implementation
for a family lives in its own branch (`Dev/<Family>` for development, `Releases/<Family>` for the released versions), so
a module or an application written against the interface does not change when the MCU family changes.

This README is the landing page and the **specification of the interface** (master). The family branches contain their
own README with everything that is specific to the family: the instances of the device, their settings and the status of
the implementation.

> **Status: implementation (branch `Dev/STM32H5`).** The STM32H5 family is implemented: modular
> arithmetic, RSA exponentiation (normal / fast / protected) and the CRT variant, ECC scalar
> multiplication, point check, complete addition, ECDSA sign and verify, using the real PKA
> register / RAM protocol of RM0481/RM0492/RM0517. Every `Pka_Set_*` operation of this
> implementation finishes synchronously inside its call (see the deviation note in `Pka.c`)
> instead of the asynchronous flow described below; the configured complete callback is still
> invoked. On STM32H503 (no PKA peripheral) every function checks `defined(PKA)` and
> returns `PKA_REQUEST_ERROR`. Unit tests run (host, Unity/CMock/RegMem) on the 12 STM32H5 lines;
> integration tests run on NUCLEO-H563ZI (limited mode: only the ECDSA verification), NUCLEO-H533RE (full mode) and
> NUCLEO-H503RB (no PKA, ignored). Their ECDSA P-256 and
> RSA-512 known-answer vectors are not official NIST CAVP vectors (not available to this change);
> they are self-consistent vectors generated and cross-checked by a from-scratch Python P-256 /
> RSA reference written for the tests, using the real curve, the real algorithm, and real
> probable primes - see the file header of `Tests/IntegrationTests/ItTest_Pka.c`.

---

## Intent and purpose

- Typical users are the **verification of a signature** (a secure boot, a firmware update: ECDSA or RSA over the digest
  of the Hash module), the **creation of a signature** (a device certificate, a challenge-response authentication), the
  **key agreement** (ECDH on the top of the scalar multiplication) and the **TLS / DTLS / secure element stacks** that
  need a fast asymmetric core. In software on a Cortex-M a 2048-bit RSA private operation or an ECDSA P-256 signature takes
  from tens of milliseconds to seconds; the accelerator is orders of magnitude faster and frees the CPU.
- The accelerator works with its own **RAM** loaded with operands in little-endian 32-bit words with a zero guard word
  and with the sizes in bits, selects the operation by a mode number and reports the result and the status in the same
  RAM. The user wants *"verify this signature of this digest with this public key on this curve"*. The module loads the
  operands (converts the byte order, pads them), starts the operation, checks the status, reads the result back,
  and **erases the RAM** when the operation handled a secret.
- The operations with a secret (the modular exponentiation with a private exponent, the scalar multiplication with a
  private scalar, the ECDSA signature) are executed in the protected mode of the accelerator that resists the side-channel
  attacks (where the device has it); the module always selects it for the operations with a secret.
- The module hides the differences between the families: the supported operations, the maximum operand sizes, the RAM
  layout and the mode numbers differ, the interface stays the same.

What the module is **not**: it does not implement a cryptographic protocol (padding schemes OAEP / PSS / PKCS#1, the ASN.1
encoding of keys and signatures, the certificates, the key generation) - they are middlewares on the top of it. It does not
generate the random number `k` of the ECDSA (the Rng module does) and it has no software fall-back for an operation the
device does not have.

---

## Concept

The operands are byte arrays (`pka_Data_t`) with the length in bytes, **big-endian** (the first byte is the most
significant one, the format of the standards and of the other crypto libraries). The module offers the operations in
groups:

| Group | Operations | Functions |
|---|---|---|
| Modular arithmetic | modular exponentiation, reduction, inversion, addition, subtraction, Montgomery multiplication, the Montgomery parameter | `Pka_Set_ModExp`, `Pka_Set_ModReduce`, `Pka_Set_ModInv`, `Pka_Set_ModAdd`, `Pka_Set_ModSub`, `Pka_Set_ModMul` |
| Arithmetic | addition, subtraction, multiplication, comparison | `Pka_Set_Arithmetic` |
| RSA | exponentiation with the public or the private exponent, exponentiation with the CRT parameters | `Pka_Set_RsaExp`, `Pka_Set_RsaCrtExp` |
| Elliptic curves | scalar multiplication, the check that a point is on the curve, the point addition, the conversion to the affine form | `Pka_Set_EccScalarMul`, `Pka_Set_EccPointCheck`, `Pka_Set_EccAdd` |
| ECDSA | signature generation, signature verification | `Pka_Set_EcdsaSign`, `Pka_Set_EcdsaVerify` |

A curve is described by `pka_Curve_t` (the prime or the modulus, the coefficients `a` and `b`, the base point, the order
of the base point and the size); the common curves are predefined constants (`PKA_CURVE_NIST_P256`, `PKA_CURVE_NIST_P384`,
`PKA_CURVE_NIST_P521`, the Brainpool curves ...) and are linked only when the application uses them.

Rules:

1. A request is accepted when the peripheral is idle (`Pka_Get_State`) and the parameters are valid: a supported operation, the
   operand sizes inside the limit of the device (`Pka_Get_MaxOperandBits`), non-`PKA_NULL_PTR` buffers, the output buffers long
   enough, a valid curve. Otherwise the call returns an error and the hardware is not touched.
2. A request is **non-blocking**: the module loads the operands, starts the operation and returns; the completion
   (an interrupt, or `Pka_Task` in the polling mode) reads the result back, checks the status of the hardware and calls the
   complete callback with the result `pka_Result_t`.
3. Results beyond "done" are meaningful: `PKA_RESULT_OK`, `PKA_RESULT_SIGNATURE_INVALID` (the verification did not pass -
   it is **not** an error of the driver), `PKA_RESULT_POINT_NOT_ON_CURVE`, `PKA_RESULT_NO_INVERSE`, `PKA_RESULT_OPERAND_ERROR`,
   `PKA_RESULT_HARDWARE_ERROR` (RAM access error, address error).
4. The PKA RAM is erased after every operation with a secret (the output buffer of the application is then the only copy)
   and by `Pka_Deinit`; `Pka_Set_RamErase` erases it on demand.
5. The module does one operation at a time; a second request while one runs returns an error.

---

## Supported families

Every family gets its own story, its own tasks and its own branches `Dev/<Family>` and `Releases/<Family>` cut from this
master.

| Family | Branch | Peripheral | Status |
|---|---|---|---|
| STM32H5 | `Dev/STM32H5` | `PKA` on every STM32H5 line except H503 (confirmed in `availability_STM32H5.md`): RSA / DH operands up to 4160 bits, ECC operands up to 640 bits, RSA exponentiation and CRT, ECC scalar multiplication, point check, complete addition, ECDSA sign and verify, modular and plain arithmetic, protection against the side-channel attacks for the operations with a secret. On H503 every function only returns `PKA_REQUEST_ERROR` (`defined(PKA)` check). H523/543/562/563xx restrict the hardware itself to ECDSA verification only (RM0481 41.3, "limited mode"): `Pka_Get_Capability` reports only `PKA_OPERATION_ECDSA_VERIFY` there, the other operations are rejected by the hardware. | implemented |
| STM32U5 | `Dev/STM32U5` | `PKA` on the lines that have it | planned |
| STM32U3 | `Dev/STM32U3` | device dependent | planned |
| STM32F4, STM32F7, STM32G4, STM32H7, STM32L4 | `Dev/STM32F4` ... | no public key accelerator on the device - the module is a stub that returns `PKA_REQUEST_ERROR` | planned |

A function without a meaning in a family stays in the interface, returns `PKA_REQUEST_ERROR` and suppresses the unused
parameters (for example the operation or the operand size the device does not support).

---

## Public interface in short (proposal)

| Group | Functions |
|---|---|
| Module management | `Pka_Get_ModuleVersion`, `Pka_Init`, `Pka_Deinit`, `Pka_Task`, `Pka_Get_DefaultConfig` |
| Capability and state | `Pka_Get_Capability`, `Pka_Get_MaxOperandBits`, `Pka_Get_State`, `Pka_Get_Result`, `Pka_Set_RamErase` |
| Arithmetic | `Pka_Set_Arithmetic`, `Pka_Set_ModExp`, `Pka_Set_ModReduce`, `Pka_Set_ModInv`, `Pka_Set_ModAdd`, `Pka_Set_ModSub`, `Pka_Set_ModMul` |
| RSA | `Pka_Set_RsaExp`, `Pka_Set_RsaCrtExp` |
| Elliptic curves | `Pka_Set_EccScalarMul`, `Pka_Set_EccPointCheck`, `Pka_Set_EccAdd` |
| ECDSA | `Pka_Set_EcdsaSign`, `Pka_Set_EcdsaVerify` |
| Interrupts | `Pka_Set_IrqPriority`, `Pka_Get_IrqPriority` |

```c
pka_ModuleVersion_t Pka_Get_ModuleVersion   ( void );

pka_RequestState_t  Pka_Init                ( const pka_Config_t * const pkaConfig );
pka_RequestState_t  Pka_Deinit              ( void );
void                Pka_Task                ( void );
pka_RequestState_t  Pka_Get_DefaultConfig   ( pka_Config_t * const pkaConfig );

pka_RequestState_t  Pka_Get_Capability      ( pka_Operation_t operation, pka_FunctionState_t * const supported );
pka_RequestState_t  Pka_Get_MaxOperandBits  ( pka_OperandType_t operandType, pka_Bits_t * const maxBits );
pka_RequestState_t  Pka_Get_State           ( pka_State_t * const pkaState );
pka_RequestState_t  Pka_Get_Result          ( pka_Result_t * const result );

pka_RequestState_t  Pka_Set_RsaExp          ( const pka_RsaExpRequest_t * const request );
pka_RequestState_t  Pka_Set_RsaCrtExp       ( const pka_RsaCrtRequest_t * const request );

pka_RequestState_t  Pka_Set_EccScalarMul    ( const pka_Curve_t * const curve, const pka_Data_t * const scalar, const pka_EccPoint_t * const point, pka_EccPoint_t * const result );
pka_RequestState_t  Pka_Set_EcdsaSign       ( const pka_Curve_t * const curve, const pka_Data_t * const privateKey, const pka_Data_t * const randomK, const pka_Data_t * const digest, pka_DataCnt_t digestSize, pka_EcdsaSignature_t * const signature );
pka_RequestState_t  Pka_Set_EcdsaVerify     ( const pka_Curve_t * const curve, const pka_EccPoint_t * const publicKey, const pka_EcdsaSignature_t * const signature, const pka_Data_t * const digest, pka_DataCnt_t digestSize );

pka_RequestState_t  Pka_Set_RamErase        ( void );
```

Every function returns `PKA_REQUEST_OK` / `PKA_REQUEST_ERROR` (the request was accepted and started) and checks its
parameters and the state of the module before it touches a register. The outcome of the operation is `pka_Result_t`.

| Type | Meaning |
|---|---|
| `pka_Config_t` | Transfer mode (`PKA_XFER_MODE_POLL` / `ISR`), interrupt priority, callbacks (complete, error) |
| `pka_Data_t` | Big-endian byte of an operand; the size is passed next to the pointer |
| `pka_Curve_t` | Prime / modulus, `a` (absolute value and sign), `b`, base point, order, size in bytes |
| `pka_EccPoint_t` | `X` and `Y` coordinates (big-endian) |
| `pka_EcdsaSignature_t` | `R` and `S` (big-endian) |
| `pka_RsaExpRequest_t`, `pka_RsaCrtRequest_t` | Modulus, exponent (or `p`, `q`, `dP`, `dQ`, `qInv`), input, output, and the flag that the exponent is a secret |
| `pka_Result_t` | `PKA_RESULT_OK`, `PKA_RESULT_SIGNATURE_INVALID`, `PKA_RESULT_POINT_NOT_ON_CURVE`, `PKA_RESULT_NO_INVERSE`, `PKA_RESULT_OPERAND_ERROR`, `PKA_RESULT_HARDWARE_ERROR` |

---

## Usage

### Verification of an ECDSA P-256 signature (secure boot, update)

```c
#include "Pka_Port.h"

static volatile pka_Result_t verifyResult;

static void App_PkaDone( pka_Result_t result )
{
    verifyResult = result;      /* PKA_RESULT_OK - the signature is valid */
}

pka_Config_t pkaConfig;

(void)Pka_Get_DefaultConfig( &pkaConfig );
pkaConfig.XferMode         = PKA_XFER_MODE_ISR;
pkaConfig.CompleteCallback = App_PkaDone;
(void)Pka_Init( &pkaConfig );

/* the digest comes from the Hash module (SHA-256 of the image) */
(void)Pka_Set_EcdsaVerify( &PKA_CURVE_NIST_P256, &publicKey, &signature, digest, 32u );
```

### ECDSA signature

```c
(void)Rng_Get_Data( RNG_PERIPH_1, &randomData );         /* a fresh k, 1 < k < n, never reused */

(void)Pka_Set_EcdsaSign( &PKA_CURVE_NIST_P256, privateKey, randomK, digest, 32u, &signature );
```

### RSA-2048 private operation with the CRT

```c
const pka_RsaCrtRequest_t request =
{
    .P = p, .Q = q, .Dp = dp, .Dq = dq, .Qinv = qInv, .OperandSize = 128u,
    .Input = input, .Output = output,
};

(void)Pka_Set_RsaCrtExp( &request );
```

---

## Behaviour and limits

- **The random `k`.** The module does not generate the nonce of the ECDSA. A repeated or a predictable `k` reveals the private
  key; take it from the Rng module (or a deterministic scheme of RFC 6979 in the middleware). The module checks only
  that `k` is in the range `1 ... n-1`.
- **Time.** The operations take from fractions of a millisecond (a modular addition) over milliseconds (ECDSA) to tens or hundreds of
  milliseconds (a 4096-bit RSA private operation); the accelerator runs without the CPU, so use the interrupt mode or
  a task that waits for the callback.
- **Secrets.** The module erases the RAM after the operations with a secret, but the application still holds the copy of
  the private key in its memory; protect and clear it. The protected (side-channel resistant) execution is slower than
  the plain one and is used for the secret operations only.
- **Operand ranges.** The operands must be smaller than the modulus (the module checks the sizes, not the values, except the
  documented ones such as `k < n` and the curve point checks), the modulus of the RSA must be odd.
- **Cache and DMA.** There is no DMA in the PKA; the operands are copied by the CPU through the registers.
- **Not part of the first version:** the padding and the encoding schemes, the key generation, the Montgomery and Edwards
  curves (X25519, Ed25519) as dedicated operations (a middleware can build them on the modular arithmetic), the batching
  of several operations.

---

## Dependencies

- **Rcc** - peripheral clock and reset
- **Nvic** - interrupt of the peripheral
- **Rng** - (the caller) the random number `k` of the ECDSA; the RNG has to be clocked and enabled (`Rng_Init`, `Rng_Set_ExecActive`) before `Pka_Init`, otherwise PKA_SR.INITOK is never set (RM0481 PKA_SR.INITOK)
- **RAL (Register Abstraction Layer)** - used internally to access the registers

All mandatory RCC and NVIC configurations are handled internally.

---

## Testing

- **Unit tests** (host, Unity + CMock + RegMem): the conversion of the operands between the big-endian bytes and the
  words of the RAM with the guard word (sizes 1 ... the maximum, the sizes that are not a multiple of the word), the
  request validation, the mapping of the hardware status to `pka_Result_t`, the erase of the RAM after the secret
  operations, the callbacks and the polling flow.
- **Integration tests** (target, probe-rs): the known-answer tests - ECDSA P-256 / P-384 sign and verify (NIST CAVP
  vectors, also the tampered signature and digest), RSA-2048 / 3072 with and without the CRT, the scalar multiplication
  and the point check on the curves, the modular arithmetic against a software big-number reference.

---

## Interface conventions

The module follows the common rules of the MCAL layer, so that it behaves like the other modules:

- **Lists instead of free members.** Everything that the hardware restricts (the pins, the kernel clock sources, the DMA
  channels, the triggers and the other selectable sources) is a `typedef enum` list with exactly the items that are valid
  for the device line; a pin is an item `PKA_<SIGNAL>_PIN_<INSTANCE>_P<port><pin>` and there is an `*_UNUSED` item. A choice
  that is not in the list cannot be written.
- **Own peripheral only.** The module calls only the registers / LL functions of its own peripheral. The clocks, the
  interrupts, the pins, the DMA and the EXTI lines go through the API of the Rcc, Nvic, Gpio, Gpdma and Exti modules; a
  missing function is added to that module, it is not bypassed.
- **Init verifies itself.** `Pka_Init` checks the result at the end; when it is not as required, the module is
  deinitialized and an error is returned. The waiting for the hardware is a loop on the register state with a timeout,
  never a blind delay.
- **Transfer modes.** Where the module moves data, the POLL (served by `Pka_Task`), ISR and DMA modes have the same
  configuration structure, the same request and the same callbacks (error, half transfer, transfer complete).
- **Flags and states are enums of the module** (`pka_FunctionState_t`, `pka_FlagState_t`), the limits and the constants are
  named, there are no magic numbers in the interface.
- **Unsupported functions stay.** A function without a meaning in a family keeps its signature, suppresses the unused
  parameters and returns `PKA_REQUEST_ERROR`.
- **Documentation.** Every function and type has a Doxygen description, the main header has the `\defgroup`.

---

## Repository layout and branches

The master holds this README and the license. The family branches (`Dev/<Family>`, `Releases/<Family>`) hold:

| Path | Content |
|---|---|
| `README.md` | README of the family: the instances of the device, specifics, errata, status |
| `Pka_Port.h`, `Pka_Types.h` | Public interface (identical in all families) |
| `Pka*.c`, `Pka.h` | Implementation of the family |
| `CMakeLists.txt` | Library `Pka_Lib` of the EmBi platform |
| `Tests/UnitTests` | Unit tests (Unity + CMock + RegMem) |
| `Tests/IntegrationTests` | Integration tests on the target (probe-rs) |

A change of the public interface is made in all families.

---

## CMake integration

```cmake
target_link_libraries( User_Lib PRIVATE Pka_Lib )
```

1. Link `Pka_Lib` to your CMake library.
2. Include `Pka_Port.h` in your project.
3. Configure the module as needed for your hardware.

---

## License

This project is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.

You are free to use, modify, and share this work for **non-commercial purposes**, provided appropriate credit is given.

See [LICENSE.md](LICENSE.md) for full terms or visit [creativecommons.org/licenses/by-nc/4.0](https://creativecommons.org/licenses/by-nc/4.0/).

---

## Authors

- **Mr.Nobody** - [embedbits.com](https://embedbits.com)

Contributions are welcome! Please open a pull request.
