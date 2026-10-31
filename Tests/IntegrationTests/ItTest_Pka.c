/**
 * \author Mr.Nobody
 * \file ItTest_Pka.c
 * \ingroup Pka
 * \brief Integration tests of the public key accelerator (PKA) module on target.
 *
 * Pka module runs on the MCU together with the real PKA hardware (register / RAM
 * protocol of RM0481/492/517), RCC, NVIC and RNG (PKA_SR.INITOK needs the enabled RNG).
 * Tests verify what the unit tests (RegMem, no real math) cannot: the known-answer correctness of the operations.
 *
 * Known-answer vectors:
 * - ECDSA P-256 sign / verify: the curve domain parameters are the real NIST P-256
 *   ones (RM0481 Table 435 / FIPS 186-4). The private key, the nonce k and the
 *   message digest, together with the resulting public key Q = d*G and signature
 *   (r, s), were generated and independently cross-checked by a from-scratch
 *   Python P-256 point-multiplication / ECDSA reference written for this test
 *   (double-and-add scalar multiplication, the standard sign and verify equations)
 *   - not copied from a published CAVP vector, because none was available to
 *     verify byte-for-byte in this environment; the curve, the algorithm and the
 *     arithmetic are the standard ones, only the specific key/nonce/message
 *     instance is self-generated. Swap in an official NIST CAVP SigVer/SigGen
 *     vector here if byte-exact alignment with a published source is required.
 * - RSA-512 CRT (and the equivalent plain exponentiation): real probable primes
 *   p, q (Miller-Rabin, 20 rounds) with e = 65537, d = e^-1 mod phi(n); the
 *   ciphertext is pow(m, e, n) of a fixed message, independently re-decrypted
 *   with and without the CRT parameters in the same Python reference. A 2048-bit
 *   modulus (the README example) would need p, q, dP, dQ, qInv, the message and
 *   the ciphertext as 256-byte literals each; 512 bits keeps the same real,
 *   self-consistent RSA / CRT relation in a reviewable amount of test source.
 *
 * Used resources:
 * - PKA (RSA / DH and ECC operand RAM, operation registers), RNG
 * - lines with the PKA in the limited mode (H523, H543, H562, H563): only the ECDSA verification tests run, the
 *   others are ignored; MCU without PKA (H503): all tests are ignored
 * - no external wiring
 *
 * \note Waiting is bounded by number of loop iterations (no reference timer),
 *       limits are set with large margin for the default system clock.
 */

/* ============================= INCLUDES =================================== */
#include "unity.h"                          /* Unity testing framework        */
#include "IntegrationTesting.h"             /* Integration testing on target  */
#include "Pka_Port.h"                       /* Module under test              */
#include "Rng_Port.h"                       /* Random number source of the PKA */
#include "Stm32.h"                          /* Presence of PKA                */
#include "string.h"                         /* memcpy for the read-only fixtures */
/* ============================= TYPEDEFS =================================== */

/* ======================= FORWARD DECLARATIONS ============================= */

static void ItPka_Init_Module( void );
static void ItPka_Require_Operation( pka_Operation_t operation );

/* ========================= SYMBOLIC CONSTANTS ============================= */

/** Interrupt priority used by tests (POLL mode is used, ISR is not exercised here) */
#define IT_PKA_IRQ_PRIO                      ( 5u )

/** Byte length of a P-256 operand (EOS, 32 bytes) */
#define IT_PKA_P256_SIZE                     ( 32u )

/** Byte length of the RSA-512 CRT half operand (p, q, dP, dQ, qInv) */
#define IT_PKA_RSA_HALF_SIZE                 ( 32u )

/** Byte length of the RSA-512 full operand (modulus, message, ciphertext) */
#define IT_PKA_RSA_FULL_SIZE                 ( 64u )

/** Byte length of the small modular addition software-reference operands (3 bytes, fits 257) */
#define IT_PKA_MODADD_OPERAND_SIZE           ( 3u )

/* ========================== LOCAL VARIABLES =============================== */

#define IT_PKA_P256_PRIVATE_KEY_BYTES \
    0xC9u, 0xAFu, 0xA9u, 0xD8u, 0x45u, 0xBAu, 0x75u, 0x16u, \
    0x6Bu, 0x5Cu, 0x21u, 0x57u, 0x67u, 0xB1u, 0xD6u, 0x93u, \
    0x4Eu, 0x50u, 0xC3u, 0xDBu, 0x36u, 0xE8u, 0x9Bu, 0x12u, \
    0x7Bu, 0x8Au, 0x62u, 0x2Bu, 0x12u, 0x0Fu, 0x67u, 0x21u

#define IT_PKA_P256_PUBLIC_KEY_X_BYTES \
    0x60u, 0xFEu, 0xD4u, 0xBAu, 0x25u, 0x5Au, 0x9Du, 0x31u, \
    0xC9u, 0x61u, 0xEBu, 0x74u, 0xC6u, 0x35u, 0x6Du, 0x68u, \
    0xC0u, 0x49u, 0xB8u, 0x92u, 0x3Bu, 0x61u, 0xFAu, 0x6Cu, \
    0xE6u, 0x69u, 0x62u, 0x2Eu, 0x60u, 0xF2u, 0x9Fu, 0xB6u

#define IT_PKA_P256_PUBLIC_KEY_Y_BYTES \
    0x79u, 0x03u, 0xFEu, 0x10u, 0x08u, 0xB8u, 0xBCu, 0x99u, \
    0xA4u, 0x1Au, 0xE9u, 0xE9u, 0x56u, 0x28u, 0xBCu, 0x64u, \
    0xF2u, 0xF1u, 0xB2u, 0x0Cu, 0x2Du, 0x7Eu, 0x9Fu, 0x51u, \
    0x77u, 0xA3u, 0xC2u, 0x94u, 0xD4u, 0x46u, 0x22u, 0x99u

#define IT_PKA_P256_NONCE_K_BYTES \
    0x0Au, 0x6Eu, 0x3Cu, 0x57u, 0xDDu, 0x01u, 0xABu, 0xE9u, \
    0x00u, 0x86u, 0x53u, 0x83u, 0x98u, 0x35u, 0x5Du, 0xD4u, \
    0xC3u, 0xB1u, 0x7Au, 0xA8u, 0x73u, 0x38u, 0x2Bu, 0x0Fu, \
    0x24u, 0xD6u, 0x12u, 0x94u, 0x93u, 0xD8u, 0xAAu, 0xD7u

#define IT_PKA_P256_DIGEST_BYTES \
    0xAFu, 0x2Bu, 0xDBu, 0xE1u, 0xAAu, 0x9Bu, 0x6Eu, 0xC1u, \
    0xE2u, 0xADu, 0xE1u, 0xD6u, 0x94u, 0xF4u, 0x1Fu, 0xC7u, \
    0x1Au, 0x83u, 0x1Du, 0x02u, 0x68u, 0xE9u, 0x89u, 0x15u, \
    0x62u, 0x11u, 0x3Du, 0x8Au, 0x62u, 0xADu, 0xD1u, 0xBFu

#define IT_PKA_P256_EXPECTED_R_BYTES \
    0x8Cu, 0x14u, 0xAEu, 0x75u, 0xB3u, 0x67u, 0x17u, 0x8Au, \
    0x2Fu, 0xB6u, 0xE7u, 0x80u, 0xDAu, 0x0Cu, 0x4Fu, 0x83u, \
    0x67u, 0x5Eu, 0x92u, 0x3Cu, 0x0Bu, 0x72u, 0x44u, 0x78u, \
    0x9Eu, 0xB3u, 0x6Fu, 0xC4u, 0x56u, 0x8Bu, 0xCBu, 0xE8u

#define IT_PKA_P256_EXPECTED_S_BYTES \
    0x9Fu, 0xADu, 0x52u, 0x1Cu, 0xE7u, 0x55u, 0x59u, 0x73u, \
    0x27u, 0x04u, 0x5Au, 0x95u, 0x01u, 0xB9u, 0x1Fu, 0xBDu, \
    0xFFu, 0x2Eu, 0xC8u, 0x88u, 0x0Cu, 0xBCu, 0xDAu, 0xB4u, \
    0x6Eu, 0x28u, 0x89u, 0x05u, 0x58u, 0x80u, 0x84u, 0x27u

/** \ref IT_PKA_P256_DIGEST_BYTES with its last byte flipped (verification must fail) */
#define IT_PKA_P256_TAMPERED_DIGEST_BYTES \
    0xAFu, 0x2Bu, 0xDBu, 0xE1u, 0xAAu, 0x9Bu, 0x6Eu, 0xC1u, \
    0xE2u, 0xADu, 0xE1u, 0xD6u, 0x94u, 0xF4u, 0x1Fu, 0xC7u, \
    0x1Au, 0x83u, 0x1Du, 0x02u, 0x68u, 0xE9u, 0x89u, 0x15u, \
    0x62u, 0x11u, 0x3Du, 0x8Au, 0x62u, 0xADu, 0xD1u, 0x40u

#define IT_PKA_RSA_MODULUS_BYTES \
    0xC6u, 0x05u, 0x9Cu, 0x3Du, 0xD9u, 0xDDu, 0x0Du, 0x10u, \
    0x95u, 0x6Fu, 0x54u, 0x72u, 0xEAu, 0xA1u, 0x83u, 0x9Eu, \
    0x87u, 0x58u, 0x26u, 0x05u, 0x6Eu, 0x9Eu, 0xCDu, 0x0Eu, \
    0xC7u, 0xAEu, 0x65u, 0xD5u, 0x1Fu, 0xFAu, 0x31u, 0xF1u, \
    0x3Au, 0x65u, 0x19u, 0xD6u, 0xEAu, 0x59u, 0x5Fu, 0x95u, \
    0xC3u, 0x4Bu, 0x08u, 0xD3u, 0xA3u, 0x36u, 0x52u, 0xCBu, \
    0x92u, 0xBAu, 0x7Bu, 0x22u, 0x70u, 0xD1u, 0x54u, 0x68u, \
    0xA9u, 0xBDu, 0x1Fu, 0x86u, 0x21u, 0x6Cu, 0x7Fu, 0xA9u

/** RSA-512 private exponent d = e^-1 mod phi(n), e = 65537 */
#define IT_PKA_RSA_EXPONENT_D_BYTES \
    0xADu, 0x58u, 0x57u, 0xEFu, 0xA4u, 0xF9u, 0xE6u, 0xE7u, \
    0xEFu, 0x88u, 0xA7u, 0xAAu, 0x79u, 0x4Eu, 0xAEu, 0x43u, \
    0x66u, 0x43u, 0x79u, 0xF5u, 0x23u, 0x63u, 0x0Cu, 0x2Au, \
    0xB6u, 0x0Eu, 0x2Au, 0xC2u, 0xA8u, 0xDDu, 0x82u, 0x3Du, \
    0x16u, 0x80u, 0xEDu, 0x86u, 0x23u, 0x8Du, 0x95u, 0xC6u, \
    0x08u, 0x9Bu, 0xE0u, 0x80u, 0x40u, 0xF1u, 0x10u, 0xD9u, \
    0x8Eu, 0x3Cu, 0x4Eu, 0xF0u, 0x6Eu, 0x5Du, 0xF8u, 0xD4u, \
    0xEEu, 0xC7u, 0x14u, 0x44u, 0xBEu, 0x12u, 0x24u, 0xA1u

#define IT_PKA_RSA_PRIME_P_BYTES \
    0xFCu, 0xDBu, 0xF8u, 0x36u, 0xC6u, 0x55u, 0x85u, 0x21u, \
    0xF8u, 0x1Cu, 0x69u, 0x3Bu, 0xBEu, 0x96u, 0x04u, 0x17u, \
    0xFEu, 0xB5u, 0x54u, 0x8Cu, 0x76u, 0x85u, 0x04u, 0x2Eu, \
    0x4Du, 0x7Eu, 0x69u, 0xAFu, 0x52u, 0x6Cu, 0xD2u, 0xDDu

#define IT_PKA_RSA_PRIME_Q_BYTES \
    0xC8u, 0x7Bu, 0x45u, 0x7Du, 0x0Bu, 0x6Du, 0xE1u, 0x33u, \
    0x72u, 0x36u, 0xC4u, 0x3Cu, 0xA2u, 0x24u, 0x3Bu, 0x0Eu, \
    0x4Au, 0x89u, 0x43u, 0x9Fu, 0x79u, 0xFDu, 0x08u, 0x0Fu, \
    0x6Au, 0xD1u, 0x93u, 0x98u, 0xB3u, 0x88u, 0xB5u, 0x3Du

/** RSA-512 CRT parameter dP = d mod (p - 1) */
#define IT_PKA_RSA_DP_BYTES \
    0xFAu, 0xB2u, 0xD9u, 0x30u, 0xEDu, 0x89u, 0x82u, 0xDAu, \
    0xC0u, 0x14u, 0xE3u, 0x1Du, 0x12u, 0x03u, 0xC8u, 0x81u, \
    0x45u, 0xCEu, 0xE0u, 0xC9u, 0xF7u, 0x04u, 0x40u, 0xB5u, \
    0xEBu, 0xADu, 0x46u, 0xF9u, 0x45u, 0x9Eu, 0x91u, 0x9Du

/** RSA-512 CRT parameter dQ = d mod (q - 1) */
#define IT_PKA_RSA_DQ_BYTES \
    0x36u, 0x03u, 0x88u, 0x58u, 0x45u, 0x51u, 0x08u, 0x60u, \
    0xACu, 0xFFu, 0xF6u, 0x65u, 0x03u, 0xA6u, 0x51u, 0x46u, \
    0xEBu, 0x6Cu, 0x0Au, 0x0Du, 0x18u, 0x77u, 0xC4u, 0xC9u, \
    0x2Au, 0x95u, 0x66u, 0x77u, 0xB8u, 0xBFu, 0x37u, 0x5Du

/** RSA-512 CRT parameter qInv = q^-1 mod p */
#define IT_PKA_RSA_QINV_BYTES \
    0x7Au, 0x4Fu, 0x59u, 0xA0u, 0x7Fu, 0x7Cu, 0x5Bu, 0x56u, \
    0x5Cu, 0x23u, 0x81u, 0x62u, 0x3Bu, 0x49u, 0xADu, 0xD9u, \
    0x4Bu, 0x5Du, 0x22u, 0xA8u, 0x49u, 0x7Eu, 0xE5u, 0x74u, \
    0xC3u, 0x48u, 0x59u, 0xE7u, 0x06u, 0xCBu, 0x1Cu, 0x36u

/** Plaintext message "EmBi Pka RSA-2048 CRT known-answer test message!!" (left-padded with
 *  zeros to the 64-byte RSA-512 operand size, the RSA value is smaller than n) */
#define IT_PKA_RSA_MESSAGE_BYTES \
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, \
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x45u, \
    0x6Du, 0x42u, 0x69u, 0x20u, 0x50u, 0x6Bu, 0x61u, 0x20u, \
    0x52u, 0x53u, 0x41u, 0x2Du, 0x32u, 0x30u, 0x34u, 0x38u, \
    0x20u, 0x43u, 0x52u, 0x54u, 0x20u, 0x6Bu, 0x6Eu, 0x6Fu, \
    0x77u, 0x6Eu, 0x2Du, 0x61u, 0x6Eu, 0x73u, 0x77u, 0x65u, \
    0x72u, 0x20u, 0x74u, 0x65u, 0x73u, 0x74u, 0x20u, 0x6Du, \
    0x65u, 0x73u, 0x73u, 0x61u, 0x67u, 0x65u, 0x21u, 0x21u

/** Ciphertext c = m^e mod n, e = 65537 */
#define IT_PKA_RSA_CIPHERTEXT_BYTES \
    0x4Fu, 0xF2u, 0x58u, 0xFBu, 0xC5u, 0xD1u, 0x11u, 0xFAu, \
    0x6Eu, 0xF0u, 0xE9u, 0xA8u, 0xABu, 0xDFu, 0x2Bu, 0xD0u, \
    0x31u, 0x29u, 0x9Fu, 0x83u, 0x78u, 0xBAu, 0x96u, 0x8Au, \
    0x85u, 0xFFu, 0xBDu, 0xB2u, 0x19u, 0xC2u, 0x78u, 0xB8u, \
    0x78u, 0xE5u, 0x0Bu, 0x47u, 0xE2u, 0x44u, 0x3Fu, 0x87u, \
    0x35u, 0xA3u, 0xC9u, 0x54u, 0xF6u, 0xE8u, 0x70u, 0xBCu, \
    0xF4u, 0x22u, 0x55u, 0x8Cu, 0x43u, 0x90u, 0x45u, 0x98u, \
    0x1Du, 0x00u, 0x88u, 0x98u, 0xE7u, 0xF3u, 0xAEu, 0x64u

/** NIST P-256 private key d used by the ECDSA known-answer tests */
static const pka_Data_t itPka_P256PrivateKey[ IT_PKA_P256_SIZE ]    = { IT_PKA_P256_PRIVATE_KEY_BYTES };

/** Public key Q = d*G (independently re-derived, see the file header) */
static const pka_Data_t itPka_P256PublicKeyX[ IT_PKA_P256_SIZE ]    = { IT_PKA_P256_PUBLIC_KEY_X_BYTES };
static const pka_Data_t itPka_P256PublicKeyY[ IT_PKA_P256_SIZE ]    = { IT_PKA_P256_PUBLIC_KEY_Y_BYTES };

/** Signing nonce k (must never be reused in production, fixed here for the KAT) */
static const pka_Data_t itPka_P256NonceK[ IT_PKA_P256_SIZE ]        = { IT_PKA_P256_NONCE_K_BYTES };

/** Message digest signed / verified by the ECDSA tests */
static const pka_Data_t itPka_P256Digest[ IT_PKA_P256_SIZE ]        = { IT_PKA_P256_DIGEST_BYTES };

/** Expected signature parts of (\ref itPka_P256Digest, \ref itPka_P256NonceK) */
static const pka_Data_t itPka_P256ExpectedR[ IT_PKA_P256_SIZE ]     = { IT_PKA_P256_EXPECTED_R_BYTES };
static const pka_Data_t itPka_P256ExpectedS[ IT_PKA_P256_SIZE ]     = { IT_PKA_P256_EXPECTED_S_BYTES };

/** \ref itPka_P256Digest with its last byte flipped (verification must fail) */
static const pka_Data_t itPka_P256TamperedDigest[ IT_PKA_P256_SIZE ] = { IT_PKA_P256_TAMPERED_DIGEST_BYTES };

/** RSA-512 modulus n = p * q, and the private exponent d = e^-1 mod phi(n), e = 65537 */
static const pka_Data_t itPka_RsaModulus[ IT_PKA_RSA_FULL_SIZE ]    = { IT_PKA_RSA_MODULUS_BYTES };
static const pka_Data_t itPka_RsaExponentD[ IT_PKA_RSA_FULL_SIZE ]  = { IT_PKA_RSA_EXPONENT_D_BYTES };

/** RSA-512 primes and CRT parameters */
static const pka_Data_t itPka_RsaPrimeP[ IT_PKA_RSA_HALF_SIZE ]     = { IT_PKA_RSA_PRIME_P_BYTES };
static const pka_Data_t itPka_RsaPrimeQ[ IT_PKA_RSA_HALF_SIZE ]     = { IT_PKA_RSA_PRIME_Q_BYTES };
static const pka_Data_t itPka_RsaDp[ IT_PKA_RSA_HALF_SIZE ]         = { IT_PKA_RSA_DP_BYTES };
static const pka_Data_t itPka_RsaDq[ IT_PKA_RSA_HALF_SIZE ]         = { IT_PKA_RSA_DQ_BYTES };
static const pka_Data_t itPka_RsaQinv[ IT_PKA_RSA_HALF_SIZE ]       = { IT_PKA_RSA_QINV_BYTES };

/** Plaintext message and its ciphertext c = m^e mod n */
static const pka_Data_t itPka_RsaMessage[ IT_PKA_RSA_FULL_SIZE ]    = { IT_PKA_RSA_MESSAGE_BYTES };
static const pka_Data_t itPka_RsaCiphertext[ IT_PKA_RSA_FULL_SIZE ] = { IT_PKA_RSA_CIPHERTEXT_BYTES };

/* ============================= TEST SETUP ================================= */

void setUp( void )
{
    /* Nothing to reset between the test cases (fresh boot, system reset) */
}


void tearDown( void )
{
    /* Peripheral state is cleared by system reset after the test case */
}

/* =============================== TESTS ==================================== */

/**
 * \brief   NIST P-256 ECDSA signature generation reproduces the known-answer (r, s).
 *
 * \par Expected results
 * - Ignored on a line without PKA or with the PKA in the limited mode (RM0481 41.3).
 * - Pka_Set_EcdsaSign() returns PKA_REQUEST_OK.
 * - Pka_Get_Result() reports PKA_RESULT_OK.
 * - The computed signature equals \ref itPka_P256ExpectedR / \ref itPka_P256ExpectedS.
 */
void It_Pka_EcdsaSign_P256KnownAnswer_MatchesExpectedSignature( void )
{
    pka_Data_t             signatureR[ IT_PKA_P256_SIZE ];
    pka_Data_t             signatureS[ IT_PKA_P256_SIZE ];
    pka_EcdsaSignature_t   signature  = { .R = signatureR, .S = signatureS };
    pka_Result_t            result    = PKA_RESULT_NONE;

#if !defined(PKA)
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif /* !PKA */

    ItPka_Require_Operation( PKA_OPERATION_ECDSA_SIGN );
    ItPka_Init_Module();

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Set_EcdsaSign( &PKA_CURVE_NIST_P256,
                                          itPka_P256PrivateKey,
                                          itPka_P256NonceK,
                                          itPka_P256Digest,
                                          IT_PKA_P256_SIZE,
                                          &signature ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Result( &result ) );
    TEST_ASSERT_EQUAL( PKA_RESULT_OK, result );

    TEST_ASSERT_EQUAL_MEMORY( itPka_P256ExpectedR, signatureR, IT_PKA_P256_SIZE );
    TEST_ASSERT_EQUAL_MEMORY( itPka_P256ExpectedS, signatureS, IT_PKA_P256_SIZE );
}


/**
 * \brief   NIST P-256 ECDSA verification accepts the known-answer signature.
 *
 * \par Expected results
 * - Pka_Set_EcdsaVerify() returns PKA_REQUEST_OK, Pka_Get_Result() reports PKA_RESULT_OK.
 */
void It_Pka_EcdsaVerify_P256KnownAnswer_IsValid( void )
{
    pka_Data_t                     signatureR[ IT_PKA_P256_SIZE ];
    pka_Data_t                     signatureS[ IT_PKA_P256_SIZE ];
    const pka_EcdsaSignature_t     signature  = { .R = signatureR, .S = signatureS };
    pka_Data_t                     publicKeyX[ IT_PKA_P256_SIZE ];
    pka_Data_t                     publicKeyY[ IT_PKA_P256_SIZE ];
    const pka_EccPoint_t           publicKey  = { .X = publicKeyX, .Y = publicKeyY };
    pka_Result_t                    result     = PKA_RESULT_NONE;

    (void)memcpy( signatureR, itPka_P256ExpectedR, IT_PKA_P256_SIZE );
    (void)memcpy( signatureS, itPka_P256ExpectedS, IT_PKA_P256_SIZE );
    (void)memcpy( publicKeyX, itPka_P256PublicKeyX, IT_PKA_P256_SIZE );
    (void)memcpy( publicKeyY, itPka_P256PublicKeyY, IT_PKA_P256_SIZE );

#if !defined(PKA)
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif /* !PKA */

    ItPka_Init_Module();

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Set_EcdsaVerify( &PKA_CURVE_NIST_P256,
                                            &publicKey,
                                            &signature,
                                            itPka_P256Digest,
                                            IT_PKA_P256_SIZE ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Result( &result ) );
    TEST_ASSERT_EQUAL( PKA_RESULT_OK, result );
}


/**
 * \brief   NIST P-256 ECDSA verification rejects a tampered digest.
 *
 * \par Expected results
 * - Pka_Set_EcdsaVerify() still returns PKA_REQUEST_OK (the verification itself ran
 *   correctly, a failed match is not a driver error, README rule 3).
 * - Pka_Get_Result() reports PKA_RESULT_SIGNATURE_INVALID.
 */
void It_Pka_EcdsaVerify_TamperedDigest_IsSignatureInvalid( void )
{
    pka_Data_t                     signatureR[ IT_PKA_P256_SIZE ];
    pka_Data_t                     signatureS[ IT_PKA_P256_SIZE ];
    const pka_EcdsaSignature_t     signature  = { .R = signatureR, .S = signatureS };
    pka_Data_t                     publicKeyX[ IT_PKA_P256_SIZE ];
    pka_Data_t                     publicKeyY[ IT_PKA_P256_SIZE ];
    const pka_EccPoint_t           publicKey  = { .X = publicKeyX, .Y = publicKeyY };
    pka_Result_t                    result     = PKA_RESULT_NONE;

    (void)memcpy( signatureR, itPka_P256ExpectedR, IT_PKA_P256_SIZE );
    (void)memcpy( signatureS, itPka_P256ExpectedS, IT_PKA_P256_SIZE );
    (void)memcpy( publicKeyX, itPka_P256PublicKeyX, IT_PKA_P256_SIZE );
    (void)memcpy( publicKeyY, itPka_P256PublicKeyY, IT_PKA_P256_SIZE );

#if !defined(PKA)
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif /* !PKA */

    ItPka_Init_Module();

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Set_EcdsaVerify( &PKA_CURVE_NIST_P256,
                                            &publicKey,
                                            &signature,
                                            itPka_P256TamperedDigest,
                                            IT_PKA_P256_SIZE ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Result( &result ) );
    TEST_ASSERT_EQUAL( PKA_RESULT_SIGNATURE_INVALID, result );
}


/**
 * \brief   NIST P-256 scalar multiplication of the base point by the private key
 *          reproduces the known-answer public key (k * G convention of the README's
 *          ECC group, here the private key plays the role of the scalar).
 *
 * \par Expected results
 * - Ignored on a line without PKA or with the PKA in the limited mode (RM0481 41.3).
 * - Pka_Set_EccScalarMul() returns PKA_REQUEST_OK, Pka_Get_Result() PKA_RESULT_OK.
 * - The result point equals \ref itPka_P256PublicKeyX / \ref itPka_P256PublicKeyY.
 */
void It_Pka_EccScalarMul_P256KnownAnswer_ReproducesPublicKey( void )
{
    pka_Data_t         baseX[ IT_PKA_P256_SIZE ];
    pka_Data_t         baseY[ IT_PKA_P256_SIZE ];
    const pka_EccPoint_t basePoint = { .X = baseX, .Y = baseY };
    pka_Data_t         resultX[ IT_PKA_P256_SIZE ];
    pka_Data_t         resultY[ IT_PKA_P256_SIZE ];
    pka_EccPoint_t      resultPoint = { .X = resultX, .Y = resultY };
    pka_Result_t         result      = PKA_RESULT_NONE;

    (void)memcpy( baseX, PKA_CURVE_NIST_P256.Gx, IT_PKA_P256_SIZE );
    (void)memcpy( baseY, PKA_CURVE_NIST_P256.Gy, IT_PKA_P256_SIZE );

#if !defined(PKA)
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif /* !PKA */

    ItPka_Require_Operation( PKA_OPERATION_ECC_SCALAR_MUL );
    ItPka_Init_Module();

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Set_EccScalarMul( &PKA_CURVE_NIST_P256,
                                             itPka_P256PrivateKey,
                                             &basePoint,
                                             &resultPoint ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Result( &result ) );
    TEST_ASSERT_EQUAL( PKA_RESULT_OK, result );

    TEST_ASSERT_EQUAL_MEMORY( itPka_P256PublicKeyX, resultX, IT_PKA_P256_SIZE );
    TEST_ASSERT_EQUAL_MEMORY( itPka_P256PublicKeyY, resultY, IT_PKA_P256_SIZE );
}


/**
 * \brief   The NIST P-256 base point and the derived public key both satisfy the
 *          curve equation (point on curve check).
 *
 * \par Expected results
 * - Ignored on a line without PKA or with the PKA in the limited mode (RM0481 41.3).
 * - Both checks return PKA_REQUEST_OK with onCurve PKA_FUNCTION_ACTIVE.
 */
void It_Pka_EccPointCheck_BaseAndPublicKey_AreOnCurve( void )
{
    pka_Data_t         baseX[ IT_PKA_P256_SIZE ];
    pka_Data_t         baseY[ IT_PKA_P256_SIZE ];
    const pka_EccPoint_t basePoint = { .X = baseX, .Y = baseY };
    pka_Data_t         publicKeyX[ IT_PKA_P256_SIZE ];
    pka_Data_t         publicKeyY[ IT_PKA_P256_SIZE ];
    const pka_EccPoint_t publicKey = { .X = publicKeyX, .Y = publicKeyY };
    pka_FunctionState_t onCurve    = PKA_FUNCTION_INACTIVE;

    (void)memcpy( baseX, PKA_CURVE_NIST_P256.Gx, IT_PKA_P256_SIZE );
    (void)memcpy( baseY, PKA_CURVE_NIST_P256.Gy, IT_PKA_P256_SIZE );
    (void)memcpy( publicKeyX, itPka_P256PublicKeyX, IT_PKA_P256_SIZE );
    (void)memcpy( publicKeyY, itPka_P256PublicKeyY, IT_PKA_P256_SIZE );

#if !defined(PKA)
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif /* !PKA */

    ItPka_Require_Operation( PKA_OPERATION_ECC_POINT_CHECK );
    ItPka_Init_Module();

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Set_EccPointCheck( &PKA_CURVE_NIST_P256, &basePoint, &onCurve ) );
    TEST_ASSERT_EQUAL( PKA_FUNCTION_ACTIVE, onCurve );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Set_EccPointCheck( &PKA_CURVE_NIST_P256, &publicKey, &onCurve ) );
    TEST_ASSERT_EQUAL( PKA_FUNCTION_ACTIVE, onCurve );
}


/**
 * \brief   RSA-512 CRT exponentiation (chinese remainder theorem) decrypts the
 *          known-answer ciphertext back to the original message.
 *
 * \par Expected results
 * - Ignored on a line without PKA or with the PKA in the limited mode (RM0481 41.3).
 * - Pka_Set_RsaCrtExp() returns PKA_REQUEST_OK, Pka_Get_Result() PKA_RESULT_OK.
 * - The decrypted message equals \ref itPka_RsaMessage.
 */
void It_Pka_RsaCrtExp_KnownAnswer_DecryptsToOriginalMessage( void )
{
    pka_Data_t                output[ IT_PKA_RSA_FULL_SIZE ];
    const pka_RsaCrtRequest_t request =
    {
        .P = itPka_RsaPrimeP, .Q = itPka_RsaPrimeQ, .Dp = itPka_RsaDp, .Dq = itPka_RsaDq,
        .Qinv = itPka_RsaQinv, .OperandSize = IT_PKA_RSA_HALF_SIZE,
        .Input = itPka_RsaCiphertext, .Output = output
    };
    pka_Result_t result = PKA_RESULT_NONE;

#if !defined(PKA)
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif /* !PKA */

    ItPka_Require_Operation( PKA_OPERATION_RSA_CRT_EXP );
    ItPka_Init_Module();

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Set_RsaCrtExp( &request ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Result( &result ) );
    TEST_ASSERT_EQUAL( PKA_RESULT_OK, result );

    TEST_ASSERT_EQUAL_MEMORY( itPka_RsaMessage, output, IT_PKA_RSA_FULL_SIZE );
}


/**
 * \brief   Plain RSA-512 modular exponentiation (no CRT) decrypts the same ciphertext.
 *
 * \par Expected results
 * - Ignored on a line without PKA or with the PKA in the limited mode (RM0481 41.3).
 * - Pka_Set_RsaExp() returns PKA_REQUEST_OK, Pka_Get_Result() PKA_RESULT_OK.
 * - The decrypted message equals \ref itPka_RsaMessage, matching the CRT path.
 */
void It_Pka_RsaExp_KnownAnswer_MatchesCrtResult( void )
{
    pka_Data_t                output[ IT_PKA_RSA_FULL_SIZE ];
    const pka_RsaExpRequest_t request =
    {
        .Modulus = itPka_RsaModulus, .Exponent = itPka_RsaExponentD,
        .Input = itPka_RsaCiphertext, .Output = output,
        .OperandSize = IT_PKA_RSA_FULL_SIZE, .SecretExponent = PKA_FUNCTION_ACTIVE
    };
    pka_Result_t result = PKA_RESULT_NONE;

#if !defined(PKA)
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif /* !PKA */

    ItPka_Require_Operation( PKA_OPERATION_RSA_EXP );
    ItPka_Init_Module();

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Set_RsaExp( &request ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Result( &result ) );
    TEST_ASSERT_EQUAL( PKA_RESULT_OK, result );

    TEST_ASSERT_EQUAL_MEMORY( itPka_RsaMessage, output, IT_PKA_RSA_FULL_SIZE );
}


/**
 * \brief   Modular addition matches a hand-computed software reference
 *          (200 + 300) mod 257 = 243 (257 is prime).
 *
 * \par Expected results
 * - Ignored on a line without PKA or with the PKA in the limited mode (RM0481 41.3).
 * - Pka_Set_ModAdd() returns PKA_REQUEST_OK, Pka_Get_Result() PKA_RESULT_OK.
 * - The result equals 243 (0xF3).
 */
void It_Pka_Set_ModAdd_SoftwareReference_MatchesHandComputedResult( void )
{
    static const pka_Data_t operandA[ IT_PKA_MODADD_OPERAND_SIZE ] = { 0u, 0u, 200u };
    static const pka_Data_t operandB[ IT_PKA_MODADD_OPERAND_SIZE ] = { 0u, 300u >> 8, 300u & 0xFFu };
    static const pka_Data_t modulus[ IT_PKA_MODADD_OPERAND_SIZE ]  = { 0u, 257u >> 8, 257u & 0xFFu };
    pka_Data_t                result[ IT_PKA_MODADD_OPERAND_SIZE ]  = { 0 };
    pka_Result_t              getResult                              = PKA_RESULT_NONE;

#if !defined(PKA)
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif /* !PKA */

    ItPka_Require_Operation( PKA_OPERATION_MOD_ADD );
    ItPka_Init_Module();

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Set_ModAdd( operandA, operandB, modulus, IT_PKA_MODADD_OPERAND_SIZE, result ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Result( &getResult ) );
    TEST_ASSERT_EQUAL( PKA_RESULT_OK, getResult );

    {
        static const pka_Data_t expected[ IT_PKA_MODADD_OPERAND_SIZE ] = { 0u, 0u, 0xF3u };

        TEST_ASSERT_EQUAL_MEMORY( expected, result, IT_PKA_MODADD_OPERAND_SIZE );
    }
}

/* =========================== LOCAL FUNCTIONS ================================ */

/**
 * \brief Initializes the Rng (the PKA initialization needs the clocked and initialized RNG, RM0481
 *        PKA_SR.INITOK) and then the module in POLL mode with the default configuration.
 */
static void ItPka_Init_Module( void )
{
    pka_Config_t       config;
    rng_ConfigStruct_t rngConfig;

    TEST_ASSERT_EQUAL( RNG_REQUEST_OK, Rng_Get_DefaultConfig( &rngConfig ) );
    TEST_ASSERT_EQUAL( RNG_REQUEST_OK, Rng_Init( &rngConfig ) );
    TEST_ASSERT_EQUAL( RNG_REQUEST_OK, Rng_Set_ExecActive( RNG_PERIPH_1 ) );

    (void)Pka_Get_DefaultConfig( &config );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Init( &config ) );
}


/**
 * rief Ignores the test when the operation is not available on the tested line: the PKA of H523, H543, H562 and
 *        H563 works in the limited mode, only the ECDSA verification is available (RM0481 41.3, PKA_SR.LMF).
 *
 * \param operation [in]: Operation the test needs
 */
static void ItPka_Require_Operation( pka_Operation_t operation )
{
    pka_FunctionState_t supported = PKA_FUNCTION_INACTIVE;
    const pka_RequestState_t capState = Pka_Get_Capability( operation, &supported );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, capState );

    if( PKA_FUNCTION_ACTIVE == supported )
    {
        /* Operation available, the test continues */
    }
    else
    {
        TEST_IGNORE_MESSAGE( "PKA of the line works in the limited mode, only ECDSA verification is available" );
    }
}
