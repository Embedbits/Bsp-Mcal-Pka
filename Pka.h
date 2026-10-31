/**
 * \author Mr.Nobody
 * \file Pka.h
 * \ingroup Pka
 * \brief Pka module common functionality header file.
 *
 * This file contains the common functionality used internally by the module:
 * the MODE[5:0] operation codes and the PKA RAM offsets of every operation, both
 * taken from RM0481/RM0492/RM0517, chapter "Public key accelerator (PKA)",
 * sections 41.5.x and 41.8.1. Offsets are relative to the PKA base address, as
 * given by the reference manual (\ref Pka_Reg.h converts them to RAM word indexes).
 *
 */

#ifndef PKA_PKA_H
#define PKA_PKA_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================= INCLUDES =================================== */
#include "Pka_Types.h"                      /* Module types definitions       */
/* ============================= TYPEDEFS =================================== */

/** \brief PKA_CR.MODE[5:0] operation codes (RM, section 41.8.1) */
typedef enum
{
    PKA_MODE_MODEXP_MONTGOMERY_THEN_EXP = 0x00u, /**< Montgomery parameter then modular exponentiation    */
    PKA_MODE_MONTGOMERY_PARAM_ONLY      = 0x01u, /**< Montgomery parameter computation only               */
    PKA_MODE_MODEXP_FAST                = 0x02u, /**< Modular exponentiation, fast mode                   */
    PKA_MODE_MODEXP_PROTECTED           = 0x03u, /**< Modular exponentiation, protected mode              */
    PKA_MODE_RSA_CRT_EXP                = 0x07u, /**< RSA CRT exponentiation                              */
    PKA_MODE_MOD_INV                    = 0x08u, /**< Modular inversion                                   */
    PKA_MODE_ARITHMETIC_ADD             = 0x09u, /**< Arithmetic addition                                 */
    PKA_MODE_ARITHMETIC_SUB             = 0x0Au, /**< Arithmetic subtraction                              */
    PKA_MODE_ARITHMETIC_MUL             = 0x0Bu, /**< Arithmetic multiplication                           */
    PKA_MODE_ARITHMETIC_CMP             = 0x0Cu, /**< Arithmetic comparison                               */
    PKA_MODE_MOD_REDUCE                 = 0x0Du, /**< Modular reduction                                   */
    PKA_MODE_MOD_ADD                    = 0x0Eu, /**< Modular addition                                    */
    PKA_MODE_MOD_SUB                    = 0x0Fu, /**< Modular subtraction                                 */
    PKA_MODE_MONTGOMERY_MUL             = 0x10u, /**< Montgomery / modular multiplication                 */
    PKA_MODE_ECC_SCALAR_MUL             = 0x20u, /**< Montgomery parameter then ECC scalar multiplication */
    PKA_MODE_ECC_COMPLETE_ADD           = 0x23u, /**< ECC complete addition                               */
    PKA_MODE_ECDSA_SIGN                 = 0x24u, /**< ECDSA sign                                          */
    PKA_MODE_ECDSA_VERIFY               = 0x26u, /**< ECDSA verification                                  */
    PKA_MODE_ECC_DOUBLE_BASE_LADDER     = 0x27u, /**< ECC double base ladder                              */
    PKA_MODE_ECC_POINT_CHECK            = 0x28u, /**< Point on elliptic curve Fp check                    */
    PKA_MODE_ECC_PROJECTIVE_TO_AFFINE   = 0x2Fu  /**< ECC projective to affine                            */
}   pka_ModeCode_t;

/** \brief Generic hardware status reported in a 64-bit error / result slot of the PKA RAM */
typedef enum
{
    PKA_STATUS_OK                         = 0xD60Du, /**< Operation completed without error (all tables)        */
    PKA_STATUS_ERROR                      = 0xCBC9u, /**< Operation failed (modular exponentiation, ECC scalar) */
    PKA_STATUS_POINT_NOT_ON_CURVE_OR_FAIL = 0xA3B7u, /**< Point not on curve / invalid signature / infinity     */
    PKA_STATUS_COORDINATE_TOO_BIG         = 0xF946u, /**< Coordinate >= modulus p, or signature part = 0        */
    PKA_STATUS_CMP_EQUAL                  = 0xED2Cu, /**< Arithmetic comparison: A = B                          */
    PKA_STATUS_CMP_GREATER                = 0x7AF8u, /**< Arithmetic comparison: A > B                          */
    PKA_STATUS_CMP_LESS                   = 0x916Au  /**< Arithmetic comparison: A < B                          */
}   pka_HwStatus_t;

/* ========================= SYMBOLIC CONSTANTS ============================= */

/** \brief PKA RAM base offset from the PKA base address (RM, 41.8.4) */
#define PKA_RAM_BASE_OFFSET                 ( 0x400u )

/** \brief PKA RAM size in bytes (RM, 41.8.4: 1334 32-bit words) */
#define PKA_RAM_SIZE_BYTES                  ( 5336u )

/* ---- Common operand length fields (RM, 41.5.1: first 64-bit slots of the RAM) ---- */
#define PKA_RAM_OFF_EXPONENT_LEN             ( 0x400u )
#define PKA_RAM_OFF_OPERAND_LEN              ( 0x408u )
#define PKA_RAM_OFF_MODULUS_LEN              ( 0x410u )

/* ---- Modular addition / subtraction (RM, Table 412 / 413), MODE 0x0E / 0x0F ---- */
#define PKA_RAM_OFF_MODADD_OPERAND_A         ( 0xA50u )
#define PKA_RAM_OFF_MODADD_OPERAND_B         ( 0xC68u )
#define PKA_RAM_OFF_MODADD_MODULUS           ( 0x1088u )
#define PKA_RAM_OFF_MODADD_RESULT            ( 0xE78u )

/* ---- Montgomery / modular multiplication (RM, Table 414), MODE 0x10 ---- */
#define PKA_RAM_OFF_MONTMUL_OPERAND_A         ( 0xA50u )
#define PKA_RAM_OFF_MONTMUL_OPERAND_B         ( 0xC68u )
#define PKA_RAM_OFF_MONTMUL_MODULUS           ( 0x1088u )
#define PKA_RAM_OFF_MONTMUL_RESULT            ( 0xE78u )

/* ---- Modular exponentiation, normal mode (RM, Table 415), MODE 0x00 ---- */
#define PKA_RAM_OFF_MODEXP_OPERAND_A          ( 0xC68u )
#define PKA_RAM_OFF_MODEXP_EXPONENT           ( 0xE78u )
#define PKA_RAM_OFF_MODEXP_MODULUS            ( 0x1088u )
#define PKA_RAM_OFF_MODEXP_RESULT             ( 0x838u )

/* ---- Modular exponentiation, protected mode (RM, Table 417), MODE 0x03 ---- */
#define PKA_RAM_OFF_MODEXP_PROT_OPERAND_A     ( 0x16C8u )
#define PKA_RAM_OFF_MODEXP_PROT_EXPONENT      ( 0x14B8u )
#define PKA_RAM_OFF_MODEXP_PROT_MODULUS       ( 0x838u )
#define PKA_RAM_OFF_MODEXP_PROT_PHI           ( 0xC68u )
#define PKA_RAM_OFF_MODEXP_PROT_RESULT        ( 0x838u )
#define PKA_RAM_OFF_MODEXP_PROT_ERROR         ( 0x1298u )

/* ---- Modular inversion (RM, Table 418), MODE 0x08 ---- */
#define PKA_RAM_OFF_MODINV_OPERAND_A          ( 0xA50u )
#define PKA_RAM_OFF_MODINV_MODULUS            ( 0xC68u )
#define PKA_RAM_OFF_MODINV_RESULT             ( 0xE78u )

/* ---- Modular reduction (RM, Table 419), MODE 0x0D ---- */
#define PKA_RAM_OFF_MODRED_OPERAND_A          ( 0xA50u )
#define PKA_RAM_OFF_MODRED_MODULUS            ( 0xC68u )
#define PKA_RAM_OFF_MODRED_RESULT             ( 0xE78u )

/* ---- Arithmetic add / sub / mul / compare (RM, Tables 420-423), MODE 0x09-0x0C ---- */
#define PKA_RAM_OFF_ARITH_OPERAND_A           ( 0xA50u )
#define PKA_RAM_OFF_ARITH_OPERAND_B           ( 0xC68u )
#define PKA_RAM_OFF_ARITH_RESULT              ( 0xE78u )

/* ---- RSA CRT exponentiation (RM, Table 424), MODE 0x07 ---- */
#define PKA_RAM_OFF_RSACRT_DP                 ( 0x730u )
#define PKA_RAM_OFF_RSACRT_DQ                 ( 0xE78u )
#define PKA_RAM_OFF_RSACRT_QINV               ( 0x948u )
#define PKA_RAM_OFF_RSACRT_P                  ( 0xB60u )
#define PKA_RAM_OFF_RSACRT_Q                  ( 0x1088u )
#define PKA_RAM_OFF_RSACRT_OPERAND_A           ( 0x12A0u )
#define PKA_RAM_OFF_RSACRT_RESULT             ( 0x838u )

/* ---- Point on elliptic curve Fp check (RM, Table 425), MODE 0x28 ---- */
#define PKA_RAM_OFF_PTCHK_A_SIGN               ( 0x410u )
#define PKA_RAM_OFF_PTCHK_A                   ( 0x418u )
#define PKA_RAM_OFF_PTCHK_B                   ( 0x520u )
#define PKA_RAM_OFF_PTCHK_MODULUS             ( 0x470u )
#define PKA_RAM_OFF_PTCHK_POINT_X              ( 0x578u )
#define PKA_RAM_OFF_PTCHK_POINT_Y              ( 0x5D0u )
#define PKA_RAM_OFF_PTCHK_RESULT              ( 0x680u )

/* ---- ECC scalar multiplication (RM, Table 426), MODE 0x20 ---- */
#define PKA_RAM_OFF_ECCMUL_N_LEN               ( 0x400u )
#define PKA_RAM_OFF_ECCMUL_P_LEN                ( 0x408u )
#define PKA_RAM_OFF_ECCMUL_A_SIGN               ( 0x410u )
#define PKA_RAM_OFF_ECCMUL_A                   ( 0x418u )
#define PKA_RAM_OFF_ECCMUL_B                   ( 0x520u )
#define PKA_RAM_OFF_ECCMUL_MODULUS             ( 0x1088u )
#define PKA_RAM_OFF_ECCMUL_SCALAR_K             ( 0x12A0u )
#define PKA_RAM_OFF_ECCMUL_POINT_X              ( 0x578u )
#define PKA_RAM_OFF_ECCMUL_POINT_Y              ( 0x470u )
#define PKA_RAM_OFF_ECCMUL_ORDER_N              ( 0xF88u )
#define PKA_RAM_OFF_ECCMUL_RESULT_X             ( 0x578u )
#define PKA_RAM_OFF_ECCMUL_RESULT_Y             ( 0x5D0u )
#define PKA_RAM_OFF_ECCMUL_ERROR               ( 0x680u )

/* ---- ECDSA sign (RM, Table 427 / 428), MODE 0x24 ---- */
#define PKA_RAM_OFF_ECDSASIGN_N_LEN            ( 0x400u )
#define PKA_RAM_OFF_ECDSASIGN_P_LEN            ( 0x408u )
#define PKA_RAM_OFF_ECDSASIGN_A_SIGN           ( 0x410u )
#define PKA_RAM_OFF_ECDSASIGN_A                ( 0x418u )
#define PKA_RAM_OFF_ECDSASIGN_B                ( 0x520u )
#define PKA_RAM_OFF_ECDSASIGN_MODULUS          ( 0x1088u )
#define PKA_RAM_OFF_ECDSASIGN_K                ( 0x12A0u )
#define PKA_RAM_OFF_ECDSASIGN_GX               ( 0x578u )
#define PKA_RAM_OFF_ECDSASIGN_GY               ( 0x470u )
#define PKA_RAM_OFF_ECDSASIGN_HASH             ( 0xFE8u )
#define PKA_RAM_OFF_ECDSASIGN_PRIVATE_KEY      ( 0xF28u )
#define PKA_RAM_OFF_ECDSASIGN_ORDER_N          ( 0xF88u )
#define PKA_RAM_OFF_ECDSASIGN_RESULT_R         ( 0x730u )
#define PKA_RAM_OFF_ECDSASIGN_RESULT_S         ( 0x788u )
#define PKA_RAM_OFF_ECDSASIGN_ERROR            ( 0xFE0u )

/* ---- ECDSA verification (RM, Table 430 / 431), MODE 0x26 ---- */
/* Re-extracted from RM0481 Table 430/431 with `pdftotext -f 1636 -l 1643` (plain mode,
 * no -layout: that flag was the source of the earlier column garbling). No `B` field
 * exists in Table 430 for ECDSA verification (only Table 425/426/427 need it). */
#define PKA_RAM_OFF_ECDSAVRFY_N_LEN            ( 0x408u )
#define PKA_RAM_OFF_ECDSAVRFY_P_LEN            ( 0x4C8u )
#define PKA_RAM_OFF_ECDSAVRFY_A_SIGN           ( 0x468u )
#define PKA_RAM_OFF_ECDSAVRFY_A                ( 0x470u )
#define PKA_RAM_OFF_ECDSAVRFY_MODULUS          ( 0x4D0u )
#define PKA_RAM_OFF_ECDSAVRFY_GX               ( 0x678u )
#define PKA_RAM_OFF_ECDSAVRFY_GY               ( 0x6D0u )
#define PKA_RAM_OFF_ECDSAVRFY_QX               ( 0x12F8u )
#define PKA_RAM_OFF_ECDSAVRFY_QY               ( 0x1350u )
#define PKA_RAM_OFF_ECDSAVRFY_SIGN_R           ( 0x10E0u )
#define PKA_RAM_OFF_ECDSAVRFY_SIGN_S           ( 0xC68u )
#define PKA_RAM_OFF_ECDSAVRFY_HASH             ( 0x13A8u )
#define PKA_RAM_OFF_ECDSAVRFY_ORDER_N          ( 0x1088u )
#define PKA_RAM_OFF_ECDSAVRFY_RESULT           ( 0x5D0u )
#define PKA_RAM_OFF_ECDSAVRFY_RESULT_R         ( 0x578u )

/* ---- ECC complete addition (RM, Table 432), MODE 0x23 (Jacobian coordinates) ---- */
#define PKA_RAM_OFF_ECCADD_P_LEN                ( 0x408u )
#define PKA_RAM_OFF_ECCADD_A_SIGN               ( 0x410u )
#define PKA_RAM_OFF_ECCADD_A                    ( 0x418u )
#define PKA_RAM_OFF_ECCADD_MODULUS              ( 0x470u )
#define PKA_RAM_OFF_ECCADD_P_X                   ( 0x628u )
#define PKA_RAM_OFF_ECCADD_P_Y                   ( 0x680u )
#define PKA_RAM_OFF_ECCADD_P_Z                   ( 0x6D8u )
#define PKA_RAM_OFF_ECCADD_Q_X                   ( 0x730u )
#define PKA_RAM_OFF_ECCADD_Q_Y                   ( 0x788u )
#define PKA_RAM_OFF_ECCADD_Q_Z                   ( 0x7E0u )
#define PKA_RAM_OFF_ECCADD_RESULT_X              ( 0xD60u )
#define PKA_RAM_OFF_ECCADD_RESULT_Y              ( 0xDB8u )
#define PKA_RAM_OFF_ECCADD_RESULT_Z              ( 0xE10u )

/** \brief 64-bit PKA word size in bytes (RM, 41.5.1: "word" denotes a 64-bit unit here) */
#define PKA_WORD_BYTES                        ( 8u )

/** \brief Bits in a PKA 64-bit RAM word */
#define PKA_WORD_BITS                         ( 64u )

/** \brief Bounded iteration count used by every busy/ready wait loop on PKA_SR */
#define PKA_REG_TIMEOUT_RAW                    ( 0x100000u )

/* ========================= EXPORTED MACROS ================================ */

/* ========================= EXPORTED VARIABLES ============================= */

/* ======================== EXPORTED FUNCTIONS ============================== */

#ifdef __cplusplus
}
#endif

#endif /* PKA_PKA_H */
