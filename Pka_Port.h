/**
 * \author Mr.Nobody
 * \file Pka_Port.h
 * \ingroup Pka
 * \brief Pka module public functionality
 *
 * This file contains all available public functionality, any other files shall not
 * be used outside of the module.
 *
 */

#ifndef PKA_PKA_PORT_H
#define PKA_PKA_PORT_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================== INCLUDES ================================== */
#include "Pka_Types.h"                      /* Module types definition        */
/* ============================== TYPEDEFS ================================== */

/* ========================== SYMBOLIC CONSTANTS ============================ */

/* ========================== EXPORTED MACROS =============================== */

/* ========================== EXPORTED VARIABLES ============================ */

extern const pka_Curve_t PKA_CURVE_NIST_P256; /**< NIST FIPS 186-4 curve P-256 */
extern const pka_Curve_t PKA_CURVE_NIST_P384; /**< NIST FIPS 186-4 curve P-384 */

/* ========================= EXPORTED FUNCTIONS ============================= */

pka_ModuleVersion_t Pka_Get_ModuleVersion  ( void );

pka_RequestState_t  Pka_Init               ( const pka_Config_t * const pkaConfig );
pka_RequestState_t  Pka_Deinit             ( void );
void                Pka_Task               ( void );
pka_RequestState_t  Pka_Get_DefaultConfig  ( pka_Config_t * const pkaConfig );

pka_RequestState_t  Pka_Get_Capability     ( pka_Operation_t operation, pka_FunctionState_t * const supported );
pka_RequestState_t  Pka_Get_MaxOperandBits ( pka_OperandType_t operandType, pka_Bits_t * const maxBits );
pka_RequestState_t  Pka_Get_State          ( pka_State_t * const pkaState );
pka_RequestState_t  Pka_Get_Result         ( pka_Result_t * const result );

/* ----------------------------- Modular arithmetic -------------------------- */

pka_RequestState_t  Pka_Set_ModAdd         ( const pka_Data_t * const a,
                                             const pka_Data_t * const b,
                                             const pka_Data_t * const modulus,
                                             pka_DataCnt_t operandSize,
                                             pka_Data_t * const result );
pka_RequestState_t  Pka_Set_ModSub         ( const pka_Data_t * const a,
                                             const pka_Data_t * const b,
                                             const pka_Data_t * const modulus,
                                             pka_DataCnt_t operandSize,
                                             pka_Data_t * const result );
pka_RequestState_t  Pka_Set_ModMul         ( const pka_Data_t * const a,
                                             const pka_Data_t * const b,
                                             const pka_Data_t * const modulus,
                                             pka_DataCnt_t operandSize,
                                             pka_Data_t * const result );
pka_RequestState_t  Pka_Set_ModExp         ( const pka_Data_t * const base,
                                             const pka_Data_t * const exponent,
                                             const pka_Data_t * const modulus,
                                             pka_DataCnt_t operandSize,
                                             pka_FunctionState_t secretExponent,
                                             pka_Data_t * const result );
pka_RequestState_t  Pka_Set_ModInv         ( const pka_Data_t * const a,
                                             const pka_Data_t * const modulus,
                                             pka_DataCnt_t operandSize,
                                             pka_Data_t * const result );
pka_RequestState_t  Pka_Set_ModReduce      ( const pka_Data_t * const a,
                                             pka_DataCnt_t aSize,
                                             const pka_Data_t * const modulus,
                                             pka_DataCnt_t operandSize,
                                             pka_Data_t * const result );

/* -------------------------------- Arithmetic -------------------------------- */

pka_RequestState_t  Pka_Set_Arithmetic     ( pka_Arithmetic_t operation,
                                             const pka_Data_t * const a,
                                             const pka_Data_t * const b,
                                             pka_DataCnt_t operandSize,
                                             pka_Data_t * const result );

/* ----------------------------------- RSA ------------------------------------ */

pka_RequestState_t  Pka_Set_RsaExp         ( const pka_RsaExpRequest_t * const request );
pka_RequestState_t  Pka_Set_RsaCrtExp      ( const pka_RsaCrtRequest_t * const request );

/* ------------------------------ Elliptic curves ------------------------------ */

pka_RequestState_t  Pka_Set_EccScalarMul   ( const pka_Curve_t * const curve,
                                             const pka_Data_t * const scalar,
                                             const pka_EccPoint_t * const point,
                                             pka_EccPoint_t * const result );
pka_RequestState_t  Pka_Set_EccPointCheck  ( const pka_Curve_t * const curve,
                                             const pka_EccPoint_t * const point,
                                             pka_FunctionState_t * const onCurve );
pka_RequestState_t  Pka_Set_EccAdd         ( const pka_Curve_t * const curve,
                                             const pka_EccPoint_t * const pointP,
                                             const pka_EccPoint_t * const pointQ,
                                             pka_EccPoint_t * const result );

/* ------------------------------------ ECDSA ---------------------------------- */

pka_RequestState_t  Pka_Set_EcdsaSign      ( const pka_Curve_t * const curve,
                                             const pka_Data_t * const privateKey,
                                             const pka_Data_t * const randomK,
                                             const pka_Data_t * const digest,
                                             pka_DataCnt_t digestSize,
                                             pka_EcdsaSignature_t * const signature );
pka_RequestState_t  Pka_Set_EcdsaVerify    ( const pka_Curve_t * const curve,
                                             const pka_EccPoint_t * const publicKey,
                                             const pka_EcdsaSignature_t * const signature,
                                             const pka_Data_t * const digest,
                                             pka_DataCnt_t digestSize );

/* ---------------------------------- Service ---------------------------------- */

pka_RequestState_t  Pka_Set_RamErase       ( void );

/* --------------------------------- Interrupts --------------------------------- */

pka_RequestState_t  Pka_Set_IrqPriority    ( pka_IrqPrio_t irqPriority );
pka_RequestState_t  Pka_Get_IrqPriority    ( pka_IrqPrio_t * const irqPriority );

#ifdef __cplusplus
}
#endif

#endif /* PKA_PKA_PORT_H */
