/**
 * \author Mr.Nobody
 * \file Pka_Reg.h
 * \ingroup Pka
 * \brief Pka module Reg component header file.
 *
 * This component contains functionality for register operations. It is private
 * to the module (the register access is not shared with other modules).
 *
 */

#ifndef PKA_REG_PKA_REG_H
#define PKA_REG_PKA_REG_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================= INCLUDES =================================== */
#include "Pka_Types.h"                      /* Module types definition        */
#include "Pka.h"                            /* MODE codes, RAM offsets        */
/* ============================= TYPEDEFS =================================== */

/** \brief List of PKA registers (banked, outside the RAM) */
typedef enum
{
    PKA_REG_CR = 0u, /**< PKA control register             */
    PKA_REG_SR,      /**< PKA status register              */
    PKA_REG_CLRFR,   /**< PKA clear flag register          */
    PKA_REG_CNT      /**< Count of available PKA registers */
}   pka_RegId_t;

/** \brief Outcome of \ref Pka_Reg_Run, distinguishing the kind of hardware error */
typedef enum
{
    PKA_REG_RUN_OK = 0u, /**< PROCENDF was set, no error flag            */
    PKA_REG_RUN_TIMEOUT, /**< PROCENDF never set within the bounded wait */
    PKA_REG_RUN_HW_ERROR /**< OPERRF / ADDRERRF / RAMERRF was set        */
}   pka_RegRunResult_t;

/* ========================= SYMBOLIC CONSTANTS ============================= */

/* ========================= EXPORTED MACROS ================================ */

/* ========================= EXPORTED VARIABLES ============================= */

/* ======================== EXPORTED FUNCTIONS ============================== */

/* ---------------------------- Generic accessors --------------------------- */

void                        Pka_Set_RegBit              ( pka_RegId_t regId, uint32_t bitMask );
void                        Pka_Reset_RegBit            ( pka_RegId_t regId, uint32_t bitMask );
uint32_t                    Pka_Get_RegBit              ( pka_RegId_t regId, uint32_t bitMask );

void                        Pka_Set_RegVal              ( pka_RegId_t regId, uint32_t regMask, uint32_t regValue );
uint32_t                    Pka_Get_RegVal              ( pka_RegId_t regId, uint32_t regMask );

/* ------------------------------- RAM access -------------------------------- */

pka_RequestState_t          Pka_Reg_Set_RamWord32       ( uint32_t ramOffset, uint32_t value );
pka_RequestState_t          Pka_Reg_Get_RamWord32       ( uint32_t ramOffset, uint32_t * const value );

pka_RequestState_t          Pka_Reg_Write_Length        ( uint32_t ramOffset, pka_Bits_t bits );

pka_RequestState_t          Pka_Reg_Write_Operand       ( uint32_t ramOffset,
                                                          const pka_Data_t * const data,
                                                          pka_DataCnt_t dataSize,
                                                          pka_DataCnt_t wordCount );
pka_RequestState_t          Pka_Reg_Read_Operand        ( uint32_t ramOffset,
                                                          pka_Data_t * const data,
                                                          pka_DataCnt_t dataSize,
                                                          pka_DataCnt_t wordCount );

pka_RequestState_t          Pka_Reg_Read_Status         ( uint32_t ramOffset, uint32_t * const status );

/* ----------------------------- Register protocol --------------------------- */

pka_RequestState_t          Pka_Reg_Set_Enable          ( void );
void                        Pka_Reg_Set_Disable         ( void );
pka_FunctionState_t         Pka_Reg_Get_InitOk          ( void );

pka_RegRunResult_t          Pka_Reg_Run                 ( pka_ModeCode_t modeCode );

pka_FunctionState_t         Pka_Reg_Get_BusyState       ( void );

void                        Pka_Reg_Set_IrqEnable       ( pka_FunctionState_t enableState );

#ifdef __cplusplus
}
#endif

#endif /* PKA_REG_PKA_REG_H */
