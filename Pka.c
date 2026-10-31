/**
 * \author Mr.Nobody
 * \file Pka.c
 * \ingroup Pka
 * \brief Pka module common functionality
 *
 * # Introduction #
 * The public key accelerator loads its operands into its own RAM (big-endian bytes
 * converted to little-endian 64-bit words with a zero guard word, \ref Pka_Reg.c),
 * selects the operation with PKA_CR.MODE[5:0], starts it and waits for PKA_SR.PROCENDF
 * (RM0481/492/517, PKA chapter, section 41.4.7 and 41.5.x).
 *
 * # Synchronous execution (deviation from the README "non-blocking" wording) #
 * Every `Pka_Set_*` function here waits (bounded, \ref PKA_REG_TIMEOUT_RAW iterations)
 * for the operation to finish before it returns, instead of starting it and leaving
 * the completion to \ref Pka_Task / the interrupt. This keeps the register-level
 * protocol of every operation in one place and easy to verify against the reference
 * manual; \ref Pka_Task therefore never has a pending operation to finish by design
 * (kept for interface compatibility, see its own Doxygen). The configured
 * \ref pka_CompleteCallback_t is still invoked at the end of every `Pka_Set_*` call,
 * so application code written against the asynchronous contract keeps working.
 *
 * # Outcome convention #
 * `Pka_Set_*` returns \ref PKA_REQUEST_OK when the hardware ran the operation without
 * a register-level error (no OPERRF / ADDRERRF / RAMERRF, no timeout) and the request
 * parameters were valid; \ref PKA_REQUEST_ERROR otherwise (parameters rejected before
 * the hardware was touched, or a register-level error). The semantic outcome of the
 * operation itself (valid / invalid signature, point on curve or not, no inverse, ...)
 * is always a successful request and is read back with \ref Pka_Get_Result.
 *
 * # Devices without the PKA peripheral #
 * The PKA exists on the STM32H5 lines whose CMSIS device header defines \c PKA (every line except
 * STM32H503, see the README availability table). Every public function checks it (\c defined(PKA)):
 * on a device without the PKA it only returns \ref PKA_REQUEST_ERROR (\ref Pka_Task does nothing,
 * \ref Pka_Get_ModuleVersion returns the version), so no separate stub file is needed.
 *
 */
/* ============================== INCLUDES ================================== */
#include "Pka.h"                            /* MODE codes, RAM offsets        */
#include "Pka_Port.h"                       /* Own port file include          */
#include "Pka_Types.h"                      /* Module types definitions       */
#include "Pka_Reg.h"                        /* Register access                */
#include "Nvic_Port.h"                      /* NVIC handler functionality     */
#include "Rcc_Port.h"                       /* RCC handler functionality      */
#include "Stm32.h"                          /* PKA registers definition       */
/* ============================== TYPEDEFS ================================== */

/** \brief Current module version (common to every family, RM0481/492/517 section 41.3) */
#define PKA_MODULE_VERSION_MAJOR            ( 1u )
#define PKA_MODULE_VERSION_MINOR            ( 0u )
#define PKA_MODULE_VERSION_PATCH            ( 0u )

/* ========================= EXPORTED FUNCTIONS ============================= */

/**
 * \brief Returns the current version of the module.
 *
 * \return The module version
 */
pka_ModuleVersion_t Pka_Get_ModuleVersion( void )
{
    const pka_ModuleVersion_t retVersion =
    {
        .Major = PKA_MODULE_VERSION_MAJOR,
        .Minor = PKA_MODULE_VERSION_MINOR,
        .Patch = PKA_MODULE_VERSION_PATCH
    };

    return ( retVersion );
}


/**
 * \brief Serves the POLL transfer mode.
 *
 * Every operation of this implementation finishes synchronously inside its
 * `Pka_Set_*` call (see the file introduction), so there is never a pending
 * operation left for this function to finish; it is kept for interface
 * compatibility with the other families / a future asynchronous version.
 */
void Pka_Task( void )
{
    return;
}

#if defined(PKA)

/** \brief Runtime data of the module */
typedef struct
{
    pka_FunctionState_t    InitState;        /**< \ref Pka_Init completed successfully     */
    pka_State_t            ModuleState;      /**< Current operating state                  */
    pka_XferMode_t         XferMode;         /**< Configured transfer mode                 */
    pka_CompleteCallback_t CompleteCallback; /**< Called at the end of every Set_* call    */
    pka_ErrorCallback_t    ErrorCallback;    /**< Called on an asynchronous hardware error */
    pka_Result_t           LastResult;       /**< Outcome of the last finished operation   */
}   pka_RuntimeData_t;

/* ======================== FORWARD DECLARATIONS ============================ */

static pka_RequestState_t Pka_Check_Ready       ( void );
static pka_DataCnt_t       Pka_Calc_WordCount    ( pka_DataCnt_t byteSize );
static pka_Bits_t           Pka_Calc_Bits          ( pka_DataCnt_t byteSize );
static pka_RequestState_t Pka_Check_OperandSize ( pka_DataCnt_t byteSize, pka_Bits_t maxBits );
static uint32_t             Pka_Calc_SignRaw      ( pka_Sign_t sign );
static void                Pka_Finish_Operation  ( pka_RegRunResult_t runResult,
                                                   pka_Result_t hwResult,
                                                   pka_RequestState_t * const retState );

static pka_RequestState_t Pka_Exec_ModExp( const pka_Data_t * const base,
                                           const pka_Data_t * const exponent,
                                           const pka_Data_t * const modulus,
                                           pka_DataCnt_t operandSize,
                                           pka_FunctionState_t secretExponent,
                                           pka_Data_t * const result );

static pka_RequestState_t Pka_Decode_PointCheck ( uint32_t statusCode, pka_FunctionState_t * const onCurve );
static pka_RequestState_t Pka_Decode_EcdsaVerify ( uint32_t statusCode );
static pka_RequestState_t Pka_Decode_EccScalarMul( uint32_t statusCode );
static pka_RequestState_t Pka_Decode_EcdsaSign   ( uint32_t statusCode );

/* ========================== SYMBOLIC CONSTANTS ============================ */

/** \brief Default interrupt priority proposed by \ref Pka_Get_DefaultConfig */
#define PKA_DEFAULT_IRQ_PRIO                ( 7u )

/** \brief The device line uses the PKA in the limited mode: only the ECDSA signature verification is available
 *         (RM0481 section 41.3: STM32H523, H543, H562 and H563xx; PKA_SR.LMF = 1) */
#if defined( STM32H523xx ) || \
    defined( STM32H543xx ) || \
    defined( STM32H562xx ) || \
    defined( STM32H563xx )
#define PKA_LIMITED_MODE                    ( PKA_FUNCTION_ACTIVE )
#else
#define PKA_LIMITED_MODE                    ( PKA_FUNCTION_INACTIVE )
#endif /* limited mode lines */

/** \brief Value of the sign field written to the PKA RAM (RM, 41.5.14 and others) */
#define PKA_RAM_SIGN_POSITIVE_RAW           ( 0u )
#define PKA_RAM_SIGN_NEGATIVE_RAW           ( 1u )

/** \brief Bits in one byte, used to convert a byte length to the bit length the hardware expects */
#define PKA_BITS_PER_BYTE                   ( 8u )

/** \brief Factor between a CRT half operand (dP, dQ, qInv, p, q, RM Table 424) and the full RSA
 *         operand, and between a plain multiplication operand and its result (RM, Table 422) */
#define PKA_DOUBLE_FACTOR                   ( 2u )

/* =============================== MACROS =================================== */

/* ========================== EXPORTED VARIABLES ============================ */

/* =========================== LOCAL VARIABLES ============================== */

/** \brief Single instance runtime data (the device has one PKA instance) */
static pka_RuntimeData_t pka_Runtime =
{
    .InitState        = PKA_FUNCTION_INACTIVE,
    .ModuleState      = PKA_STATE_UNINIT,
    .XferMode         = PKA_XFER_MODE_POLL,
    .CompleteCallback = PKA_NULL_PTR,
    .ErrorCallback    = PKA_NULL_PTR,
    .LastResult       = PKA_RESULT_NONE
};

#endif /* PKA */

/* ========================= EXPORTED FUNCTIONS ============================= */

/**
 * \brief Initializes the module: enables the clock, enables the PKA and (ISR mode)
 *        configures its NVIC interrupt.
 *
 * Verifies the result at the end (PKA_SR.INITOK read-back, rule 2.7); on failure the
 * module is deinitialized and an error is returned.
 *
 * \param pkaConfig [in]: Pointer to the configuration structure
 * \return \ref PKA_REQUEST_OK on success, \ref PKA_REQUEST_ERROR otherwise
 */
pka_RequestState_t Pka_Init( const pka_Config_t * const pkaConfig )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    if( ( PKA_NULL_PTR != pkaConfig ) &&
        ( PKA_XFER_MODE_CNT > pkaConfig->XferMode ) &&
        ( PKA_FUNCTION_INACTIVE == pka_Runtime.InitState )    )
    {
        const rcc_RequestState_t clockState = Rcc_Set_PeriphActive( RCC_PERIPH_PKA );

        if( RCC_REQUEST_OK == clockState )
        {
            const pka_RequestState_t enableState = Pka_Reg_Set_Enable();

            if( PKA_REQUEST_OK == enableState )
            {
                pka_Runtime.XferMode         = pkaConfig->XferMode;
                pka_Runtime.CompleteCallback = pkaConfig->CompleteCallback;
                pka_Runtime.ErrorCallback    = pkaConfig->ErrorCallback;

                if( PKA_XFER_MODE_ISR == pkaConfig->XferMode )
                {
                    (void)Nvic_Set_PeriphIrq_Prio( NVIC_PERIPH_IRQ_PKA, (nvic_IrqPrio_t)pkaConfig->IrqPriority );
                    (void)Nvic_Set_PeriphIrq_Active( NVIC_PERIPH_IRQ_PKA );
                    Pka_Reg_Set_IrqEnable( PKA_FUNCTION_ACTIVE );
                }
                else
                {
                    /* POLL mode, the NVIC line of the peripheral is not used */
                }

                pka_Runtime.InitState   = PKA_FUNCTION_ACTIVE;
                pka_Runtime.ModuleState = PKA_STATE_IDLE;
                retState                = PKA_REQUEST_OK;
            }
            else
            {
                /* INITOK was not confirmed, the module is deinitialized below */
                retState = PKA_REQUEST_ERROR;
            }
        }
        else
        {
            /* Clock could not be enabled, nothing else is touched */
            retState = PKA_REQUEST_ERROR;
        }
    }
    else
    {
        /* Invalid configuration or the module is already initialized */
        retState = PKA_REQUEST_ERROR;
    }

    if( PKA_REQUEST_OK != retState )
    {
        (void)Pka_Deinit();
    }
    else
    {
        /* Initialization succeeded, nothing to roll back */
    }
#else
    (void)pkaConfig;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Deinitializes the module: disables the interrupt, the PKA and its clock.
 *
 * \return \ref PKA_REQUEST_OK, \ref PKA_REQUEST_ERROR on a device without the PKA peripheral.
 */
pka_RequestState_t Pka_Deinit( void )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    Pka_Reg_Set_IrqEnable( PKA_FUNCTION_INACTIVE );
    (void)Nvic_Set_PeriphIrq_Inactive( NVIC_PERIPH_IRQ_PKA );
    Pka_Reg_Set_Disable();
    (void)Rcc_Set_PeriphInactive( RCC_PERIPH_PKA );

    pka_Runtime.InitState        = PKA_FUNCTION_INACTIVE;
    pka_Runtime.ModuleState      = PKA_STATE_UNINIT;
    pka_Runtime.CompleteCallback = PKA_NULL_PTR;
    pka_Runtime.ErrorCallback    = PKA_NULL_PTR;
    pka_Runtime.LastResult       = PKA_RESULT_NONE;
    retState                     = PKA_REQUEST_OK;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Fills \p pkaConfig with the default configuration (POLL mode, no callbacks).
 *
 * \param pkaConfig [out]: Pointer to the configuration structure
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR for a \ref PKA_NULL_PTR value.
 */
pka_RequestState_t Pka_Get_DefaultConfig( pka_Config_t * const pkaConfig )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    if( PKA_NULL_PTR != pkaConfig )
    {
        pkaConfig->XferMode         = PKA_XFER_MODE_POLL;
        pkaConfig->IrqPriority      = (pka_IrqPrio_t)PKA_DEFAULT_IRQ_PRIO;
        pkaConfig->CompleteCallback = PKA_NULL_PTR;
        pkaConfig->ErrorCallback    = PKA_NULL_PTR;
        retState                   = PKA_REQUEST_OK;
    }
    else
    {
        /* No output pointer, nothing is written */
        retState = PKA_REQUEST_ERROR;
    }
#else
    (void)pkaConfig;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Reports whether an operation group is supported by this family.
 *
 * \note On the device lines that restrict the PKA to the limited mode (RM0481
 *       section 41.3: STM32H523/543/562/563xx support only ECDSA verification),
 *       only \ref PKA_OPERATION_ECDSA_VERIFY is reported as supported. The hardware
 *       rejects every other operation there (OPERRF) and the Set_* function reports
 *       \ref PKA_REQUEST_ERROR with \ref PKA_RESULT_HARDWARE_ERROR.
 *
 * \param operation [in]:  Operation group to query
 * \param supported [out]: Pointer to the result (not changed on error)
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR for an invalid \p operation
 *         or a \ref PKA_NULL_PTR value.
 */
pka_RequestState_t Pka_Get_Capability( pka_Operation_t operation, pka_FunctionState_t * const supported )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    if( ( PKA_NULL_PTR != supported ) &&
        ( PKA_OPERATION_CNT > operation ) &&
        ( PKA_OPERATION_UNUSED != operation )    )
    {
        if( ( PKA_FUNCTION_INACTIVE == PKA_LIMITED_MODE ) ||
            ( PKA_OPERATION_ECDSA_VERIFY == operation )       )
        {
            *supported = PKA_FUNCTION_ACTIVE;
        }
        else
        {
            /* Limited mode line: only the ECDSA verification is available */
            *supported = PKA_FUNCTION_INACTIVE;
        }

        retState   = PKA_REQUEST_OK;
    }
    else
    {
        /* Invalid operation or no output pointer, nothing is written */
        retState = PKA_REQUEST_ERROR;
    }
#else
    (void)operation;
    (void)supported;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Returns the maximum operand size the hardware accepts (RM, section 41.2).
 *
 * \param operandType [in]:  RSA / DH or ECC operand family
 * \param maxBits     [out]: Pointer to the result (not changed on error)
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR for an invalid \p operandType
 *         or a \ref PKA_NULL_PTR value.
 */
pka_RequestState_t Pka_Get_MaxOperandBits( pka_OperandType_t operandType, pka_Bits_t * const maxBits )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    if( PKA_NULL_PTR != maxBits )
    {
        if( PKA_OPERAND_TYPE_RSA == operandType )
        {
            *maxBits = (pka_Bits_t)PKA_MAX_RSA_OPERAND_BITS;
            retState = PKA_REQUEST_OK;
        }
        else if( PKA_OPERAND_TYPE_ECC == operandType )
        {
            *maxBits = (pka_Bits_t)PKA_MAX_ECC_OPERAND_BITS;
            retState = PKA_REQUEST_OK;
        }
        else
        {
            /* Invalid operand type, nothing is written */
            retState = PKA_REQUEST_ERROR;
        }
    }
    else
    {
        /* No output pointer, nothing is written */
        retState = PKA_REQUEST_ERROR;
    }
#else
    (void)operandType;
    (void)maxBits;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Returns the current operating state of the module.
 *
 * \param pkaState [out]: Pointer to the state (not changed on error)
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR for a \ref PKA_NULL_PTR value.
 */
pka_RequestState_t Pka_Get_State( pka_State_t * const pkaState )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    if( PKA_NULL_PTR != pkaState )
    {
        *pkaState = pka_Runtime.ModuleState;
        retState  = PKA_REQUEST_OK;
    }
    else
    {
        /* No output pointer, nothing is written */
        retState = PKA_REQUEST_ERROR;
    }
#else
    (void)pkaState;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Returns the outcome of the last finished operation.
 *
 * \param result [out]: Pointer to the outcome (not changed on error)
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR for a \ref PKA_NULL_PTR value
 *         or when the module is not initialized.
 */
pka_RequestState_t Pka_Get_Result( pka_Result_t * const result )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    if( ( PKA_NULL_PTR         != result ) &&
        ( PKA_FUNCTION_ACTIVE  == pka_Runtime.InitState )    )
    {
        *result  = pka_Runtime.LastResult;
        retState = PKA_REQUEST_OK;
    }
    else
    {
        /* No output pointer or module not initialized, nothing is written */
        retState = PKA_REQUEST_ERROR;
    }
#else
    (void)result;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Erases the PKA RAM on demand (RM, 41.4.8: clearing EN triggers the erase).
 *
 * \return \ref PKA_REQUEST_OK on success, \ref PKA_REQUEST_ERROR if the module is
 *         busy, not initialized, or the re-enable was not confirmed (INITOK).
 */
pka_RequestState_t Pka_Set_RamErase( void )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    const pka_RequestState_t readyState = Pka_Check_Ready();

    if( PKA_REQUEST_OK == readyState )
    {
        Pka_Reg_Set_Disable();
        retState = Pka_Reg_Set_Enable();
    }
    else
    {
        /* Module busy or not initialized, nothing is touched */
    }
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Sets the NVIC priority of the PKA interrupt line.
 *
 * \param irqPriority [in]: Requested priority
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR when the NVIC rejected it.
 */
pka_RequestState_t Pka_Set_IrqPriority( pka_IrqPrio_t irqPriority )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    const nvic_RequestState_t nvicState = Nvic_Set_PeriphIrq_Prio( NVIC_PERIPH_IRQ_PKA, (nvic_IrqPrio_t)irqPriority );

    if( NVIC_REQUEST_OK == nvicState )
    {
        retState = PKA_REQUEST_OK;
    }
    else
    {
        retState = PKA_REQUEST_ERROR;
    }
#else
    (void)irqPriority;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Reads the NVIC priority of the PKA interrupt line.
 *
 * \param irqPriority [out]: Pointer to the priority (not changed on error)
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR for a \ref PKA_NULL_PTR value
 *         or when the NVIC rejected the read.
 */
pka_RequestState_t Pka_Get_IrqPriority( pka_IrqPrio_t * const irqPriority )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    if( PKA_NULL_PTR != irqPriority )
    {
        nvic_IrqPrio_t         nvicPrio  = 0u;
        const nvic_RequestState_t nvicState = Nvic_Get_PeriphIrq_Prio( NVIC_PERIPH_IRQ_PKA, &nvicPrio );

        if( NVIC_REQUEST_OK == nvicState )
        {
            *irqPriority = (pka_IrqPrio_t)nvicPrio;
            retState     = PKA_REQUEST_OK;
        }
        else
        {
            retState = PKA_REQUEST_ERROR;
        }
    }
    else
    {
        /* No output pointer, nothing is written */
        retState = PKA_REQUEST_ERROR;
    }
#else
    (void)irqPriority;
#endif /* PKA */

    return ( retState );
}

/* ----------------------------- Modular arithmetic -------------------------- */

/**
 * \brief Modular addition: result = (a + b) mod modulus (RM, Table 412, MODE 0x0E).
 */
pka_RequestState_t Pka_Set_ModAdd( const pka_Data_t * const a,
                                   const pka_Data_t * const b,
                                   const pka_Data_t * const modulus,
                                   pka_DataCnt_t operandSize,
                                   pka_Data_t * const result )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    const pka_RequestState_t readyState = Pka_Check_Ready();
    const pka_RequestState_t   sizeState = Pka_Check_OperandSize( operandSize, (pka_Bits_t)PKA_MAX_RSA_OPERAND_BITS );

    if( ( PKA_REQUEST_OK == readyState ) &&
        ( PKA_NULL_PTR  != a ) &&
        ( PKA_NULL_PTR  != b ) &&
        ( PKA_NULL_PTR  != modulus ) &&
        ( PKA_NULL_PTR  != result ) &&
        ( PKA_REQUEST_OK == sizeState )    )
    {
        const pka_DataCnt_t wordCount = Pka_Calc_WordCount( operandSize );

        pka_Runtime.ModuleState = PKA_STATE_BUSY;
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_OPERAND_LEN  , Pka_Calc_Bits( operandSize ) );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODADD_OPERAND_A, a      , operandSize, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODADD_OPERAND_B, b      , operandSize, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODADD_MODULUS   , modulus, operandSize, wordCount );

        {
            const pka_RegRunResult_t runResult = Pka_Reg_Run( PKA_MODE_MOD_ADD );

            Pka_Finish_Operation( runResult, PKA_RESULT_OK, &retState );

            if( PKA_REQUEST_OK == retState )
            {
                (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_MODADD_RESULT, result, operandSize, wordCount );
            }
            else
            {
                /* Hardware error, result buffer is not written */
            }
        }
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }
#else
    (void)a;
    (void)b;
    (void)modulus;
    (void)operandSize;
    (void)result;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Modular subtraction: result = (a - b) mod modulus (RM, Table 413, MODE 0x0F).
 */
pka_RequestState_t Pka_Set_ModSub( const pka_Data_t * const a,
                                   const pka_Data_t * const b,
                                   const pka_Data_t * const modulus,
                                   pka_DataCnt_t operandSize,
                                   pka_Data_t * const result )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    const pka_RequestState_t readyState = Pka_Check_Ready();
    const pka_RequestState_t   sizeState = Pka_Check_OperandSize( operandSize, (pka_Bits_t)PKA_MAX_RSA_OPERAND_BITS );

    if( ( PKA_REQUEST_OK == readyState ) &&
        ( PKA_NULL_PTR  != a ) &&
        ( PKA_NULL_PTR  != b ) &&
        ( PKA_NULL_PTR  != modulus ) &&
        ( PKA_NULL_PTR  != result ) &&
        ( PKA_REQUEST_OK == sizeState )    )
    {
        const pka_DataCnt_t wordCount = Pka_Calc_WordCount( operandSize );

        pka_Runtime.ModuleState = PKA_STATE_BUSY;
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_OPERAND_LEN  , Pka_Calc_Bits( operandSize ) );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODADD_OPERAND_A, a      , operandSize, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODADD_OPERAND_B, b      , operandSize, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODADD_MODULUS   , modulus, operandSize, wordCount );

        {
            const pka_RegRunResult_t runResult = Pka_Reg_Run( PKA_MODE_MOD_SUB );

            Pka_Finish_Operation( runResult, PKA_RESULT_OK, &retState );

            if( PKA_REQUEST_OK == retState )
            {
                (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_MODADD_RESULT, result, operandSize, wordCount );
            }
            else
            {
                /* Hardware error, result buffer is not written */
            }
        }
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }
#else
    (void)a;
    (void)b;
    (void)modulus;
    (void)operandSize;
    (void)result;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Modular multiplication: result = (a * b) mod modulus (RM, Table 414, MODE 0x10).
 *
 * Both operands are taken in the natural domain (Montgomery parameter computation
 * is not chained here), matching the simple use case 2 of section 41.5.5.
 */
pka_RequestState_t Pka_Set_ModMul( const pka_Data_t * const a,
                                   const pka_Data_t * const b,
                                   const pka_Data_t * const modulus,
                                   pka_DataCnt_t operandSize,
                                   pka_Data_t * const result )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    const pka_RequestState_t readyState = Pka_Check_Ready();
    const pka_RequestState_t   sizeState = Pka_Check_OperandSize( operandSize, (pka_Bits_t)PKA_MAX_RSA_OPERAND_BITS );

    if( ( PKA_REQUEST_OK == readyState ) &&
        ( PKA_NULL_PTR  != a ) &&
        ( PKA_NULL_PTR  != b ) &&
        ( PKA_NULL_PTR  != modulus ) &&
        ( PKA_NULL_PTR  != result ) &&
        ( PKA_REQUEST_OK == sizeState )    )
    {
        const pka_DataCnt_t wordCount = Pka_Calc_WordCount( operandSize );

        pka_Runtime.ModuleState = PKA_STATE_BUSY;
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_OPERAND_LEN    , Pka_Calc_Bits( operandSize ) );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MONTMUL_OPERAND_A, a      , operandSize, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MONTMUL_OPERAND_B, b      , operandSize, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MONTMUL_MODULUS   , modulus, operandSize, wordCount );

        {
            const pka_RegRunResult_t runResult = Pka_Reg_Run( PKA_MODE_MONTGOMERY_MUL );

            Pka_Finish_Operation( runResult, PKA_RESULT_OK, &retState );

            if( PKA_REQUEST_OK == retState )
            {
                (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_MONTMUL_RESULT, result, operandSize, wordCount );
            }
            else
            {
                /* Hardware error, result buffer is not written */
            }
        }
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }
#else
    (void)a;
    (void)b;
    (void)modulus;
    (void)operandSize;
    (void)result;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Modular exponentiation: result = base^exponent mod modulus (RM, Tables 415/417).
 *
 * \param base           [in]:  Base, big-endian, \p operandSize bytes
 * \param exponent       [in]:  Exponent, big-endian, \p operandSize bytes
 * \param modulus        [in]:  Modulus, big-endian, \p operandSize bytes
 * \param operandSize    [in]:  Byte length of every operand
 * \param secretExponent [in]:  \ref PKA_FUNCTION_ACTIVE selects the protected mode
 *                              (MODE 0x03), required for a private RSA exponent.
 * \param result         [out]: Result, big-endian, \p operandSize bytes
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR for an invalid parameter, a busy or
 *         not initialized module, a hardware error or a device without the PKA peripheral.
 */
pka_RequestState_t Pka_Set_ModExp( const pka_Data_t * const base,
                                   const pka_Data_t * const exponent,
                                   const pka_Data_t * const modulus,
                                   pka_DataCnt_t operandSize,
                                   pka_FunctionState_t secretExponent,
                                   pka_Data_t * const result )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    retState = Pka_Exec_ModExp( base, exponent, modulus, operandSize, secretExponent, result );
#else
    (void)base;
    (void)exponent;
    (void)modulus;
    (void)operandSize;
    (void)secretExponent;
    (void)result;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Modular inversion: result = a^-1 mod modulus (RM, Table 418, MODE 0x08).
 *
 * \note The hardware does not report a dedicated status code for "no inverse"
 *       (unlike the point check / ECDSA tables); \ref PKA_RESULT_NO_INVERSE is
 *       therefore never produced by this operation in this implementation - a
 *       composite modulus without an inverse returns \ref PKA_RESULT_OK with a
 *       result that the RM describes as "a multiple of a factor of n" (section
 *       41.5.7); the caller is responsible for validating the result if that
 *       case is possible with its modulus.
 */
pka_RequestState_t Pka_Set_ModInv( const pka_Data_t * const a,
                                   const pka_Data_t * const modulus,
                                   pka_DataCnt_t operandSize,
                                   pka_Data_t * const result )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    const pka_RequestState_t readyState = Pka_Check_Ready();
    const pka_RequestState_t   sizeState = Pka_Check_OperandSize( operandSize, (pka_Bits_t)PKA_MAX_RSA_OPERAND_BITS );

    if( ( PKA_REQUEST_OK == readyState ) &&
        ( PKA_NULL_PTR  != a ) &&
        ( PKA_NULL_PTR  != modulus ) &&
        ( PKA_NULL_PTR  != result ) &&
        ( PKA_REQUEST_OK == sizeState )    )
    {
        const pka_DataCnt_t wordCount = Pka_Calc_WordCount( operandSize );

        pka_Runtime.ModuleState = PKA_STATE_BUSY;
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_OPERAND_LEN , Pka_Calc_Bits( operandSize ) );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODINV_OPERAND_A, a      , operandSize, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODINV_MODULUS   , modulus, operandSize, wordCount );

        {
            const pka_RegRunResult_t runResult = Pka_Reg_Run( PKA_MODE_MOD_INV );

            Pka_Finish_Operation( runResult, PKA_RESULT_OK, &retState );

            if( PKA_REQUEST_OK == retState )
            {
                (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_MODINV_RESULT, result, operandSize, wordCount );
            }
            else
            {
                /* Hardware error, result buffer is not written */
            }
        }
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }
#else
    (void)a;
    (void)modulus;
    (void)operandSize;
    (void)result;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Modular reduction: result = a mod modulus, 0 <= a < 2*modulus (RM, Table 419, MODE 0x0D).
 *
 * \param a           [in]:  Value to reduce, big-endian, \p aSize bytes
 * \param aSize       [in]:  Byte length of \p a (may be up to twice \p operandSize)
 * \param modulus     [in]:  Modulus, big-endian, \p operandSize bytes
 * \param operandSize [in]:  Byte length of \p modulus and \p result
 * \param result      [out]: Result, big-endian, \p operandSize bytes
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR for an invalid parameter, a busy or
 *         not initialized module, a hardware error or a device without the PKA peripheral.
 */
pka_RequestState_t Pka_Set_ModReduce( const pka_Data_t * const a,
                                      pka_DataCnt_t aSize,
                                      const pka_Data_t * const modulus,
                                      pka_DataCnt_t operandSize,
                                      pka_Data_t * const result )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    const pka_RequestState_t readyState = Pka_Check_Ready();
    const pka_RequestState_t   sizeState = Pka_Check_OperandSize( operandSize, (pka_Bits_t)PKA_MAX_RSA_OPERAND_BITS );

    if( ( PKA_REQUEST_OK == readyState ) &&
        ( PKA_NULL_PTR  != a ) &&
        ( PKA_NULL_PTR  != modulus ) &&
        ( PKA_NULL_PTR  != result ) &&
        ( 0u             < aSize ) &&
        ( PKA_REQUEST_OK == sizeState )    )
    {
        const pka_DataCnt_t aWordCount = Pka_Calc_WordCount( aSize );
        const pka_DataCnt_t nWordCount = Pka_Calc_WordCount( operandSize );

        pka_Runtime.ModuleState = PKA_STATE_BUSY;
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_EXPONENT_LEN, Pka_Calc_Bits( aSize ) );
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_OPERAND_LEN , Pka_Calc_Bits( operandSize ) );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODRED_OPERAND_A, a      , aSize      , aWordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODRED_MODULUS   , modulus, operandSize, nWordCount );

        {
            const pka_RegRunResult_t runResult = Pka_Reg_Run( PKA_MODE_MOD_REDUCE );

            Pka_Finish_Operation( runResult, PKA_RESULT_OK, &retState );

            if( PKA_REQUEST_OK == retState )
            {
                (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_MODRED_RESULT, result, operandSize, nWordCount );
            }
            else
            {
                /* Hardware error, result buffer is not written */
            }
        }
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }
#else
    (void)a;
    (void)aSize;
    (void)modulus;
    (void)operandSize;
    (void)result;
#endif /* PKA */

    return ( retState );
}

/* -------------------------------- Arithmetic -------------------------------- */

/**
 * \brief Plain (non-modular) arithmetic: addition, subtraction, multiplication or
 *        comparison of two operands (RM, Tables 420-423, MODE 0x09-0x0C).
 *
 * \note For \ref PKA_ARITHMETIC_MUL \p result must be at least 2 * \p operandSize
 *       bytes long (the product can need twice the operand length). For
 *       \ref PKA_ARITHMETIC_CMP the comparison outcome is written as one byte
 *       in \p result[0] (\ref pka_Compare_t), the remaining bytes are not changed.
 */
pka_RequestState_t Pka_Set_Arithmetic( pka_Arithmetic_t operation,
                                       const pka_Data_t * const a,
                                       const pka_Data_t * const b,
                                       pka_DataCnt_t operandSize,
                                       pka_Data_t * const result )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    const pka_RequestState_t readyState = Pka_Check_Ready();
    const pka_RequestState_t   sizeState = Pka_Check_OperandSize( operandSize, (pka_Bits_t)PKA_MAX_RSA_OPERAND_BITS );

    if( ( PKA_REQUEST_OK == readyState ) &&
        ( PKA_NULL_PTR  != a ) &&
        ( PKA_NULL_PTR  != b ) &&
        ( PKA_NULL_PTR  != result ) &&
        ( PKA_ARITHMETIC_CNT    > operation ) &&
        ( PKA_ARITHMETIC_UNUSED != operation ) &&
        ( PKA_REQUEST_OK == sizeState )    )
    {
        const pka_DataCnt_t  wordCount = Pka_Calc_WordCount( operandSize );
        pka_ModeCode_t        modeCode  = PKA_MODE_ARITHMETIC_ADD;
        pka_DataCnt_t          resultSize = operandSize;

        if( PKA_ARITHMETIC_ADD == operation )
        {
            modeCode = PKA_MODE_ARITHMETIC_ADD;
        }
        else if( PKA_ARITHMETIC_SUB == operation )
        {
            modeCode = PKA_MODE_ARITHMETIC_SUB;
        }
        else if( PKA_ARITHMETIC_MUL == operation )
        {
            modeCode   = PKA_MODE_ARITHMETIC_MUL;
            resultSize = (pka_DataCnt_t)( (uint32_t)operandSize * PKA_DOUBLE_FACTOR );
        }
        else
        {
            modeCode = PKA_MODE_ARITHMETIC_CMP;
        }

        pka_Runtime.ModuleState = PKA_STATE_BUSY;
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_OPERAND_LEN , Pka_Calc_Bits( operandSize ) );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ARITH_OPERAND_A, a, operandSize, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ARITH_OPERAND_B, b, operandSize, wordCount );

        {
            const pka_RegRunResult_t runResult = Pka_Reg_Run( modeCode );

            Pka_Finish_Operation( runResult, PKA_RESULT_OK, &retState );

            if( ( PKA_REQUEST_OK        == retState ) &&
                ( PKA_ARITHMETIC_CMP    != operation )    )
            {
                const pka_DataCnt_t resultWordCount = Pka_Calc_WordCount( resultSize );

                (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_ARITH_RESULT, result, resultSize, resultWordCount );
            }
            else if( PKA_REQUEST_OK == retState )
            {
                uint32_t statusCode = PKA_STATUS_CMP_EQUAL;

                (void)Pka_Reg_Read_Status( PKA_RAM_OFF_ARITH_RESULT, &statusCode );

                if( (uint32_t)PKA_STATUS_CMP_GREATER == statusCode )
                {
                    result[0] = (uint8_t)PKA_COMPARE_GREATER;
                }
                else if( (uint32_t)PKA_STATUS_CMP_LESS == statusCode )
                {
                    result[0] = (uint8_t)PKA_COMPARE_LESS;
                }
                else
                {
                    result[0] = (uint8_t)PKA_COMPARE_EQUAL;
                }
            }
            else
            {
                /* Hardware error, result buffer is not written */
            }
        }
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }
#else
    (void)operation;
    (void)a;
    (void)b;
    (void)operandSize;
    (void)result;
#endif /* PKA */

    return ( retState );
}

/* ----------------------------------- RSA ------------------------------------ */

/**
 * \brief RSA modular exponentiation (public or private operation, RM Tables 415/417).
 */
pka_RequestState_t Pka_Set_RsaExp( const pka_RsaExpRequest_t * const request )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    if( PKA_NULL_PTR != request )
    {
        retState = Pka_Exec_ModExp( request->Input,
                                    request->Exponent,
                                    request->Modulus,
                                    request->OperandSize,
                                    request->SecretExponent,
                                    request->Output );
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }
#else
    (void)request;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief RSA exponentiation with the chinese remainder theorem parameters (RM, Table 424, MODE 0x07).
 *
 * \note The RAM offsets of this table (`PKA_RAM_OFF_RSACRT_*` in \ref Pka.h) were
 *       re-extracted from RM0481 with `pdftotext` plain mode (without `-layout`) and
 *       confirmed correct after the first pass of this file (layout mode) had garbled
 *       the table columns.
 */
pka_RequestState_t Pka_Set_RsaCrtExp( const pka_RsaCrtRequest_t * const request )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    const pka_RequestState_t readyState = Pka_Check_Ready();
    pka_RequestState_t sizeState = PKA_REQUEST_ERROR;

    if( PKA_NULL_PTR != request )
    {
        sizeState = Pka_Check_OperandSize( request->OperandSize,
                                           (pka_Bits_t)( PKA_MAX_RSA_OPERAND_BITS / PKA_DOUBLE_FACTOR ) );
    }
    else
    {
        sizeState = PKA_REQUEST_ERROR;
    }

    if( ( PKA_REQUEST_OK == readyState ) &&
        ( PKA_NULL_PTR  != request ) &&
        ( PKA_NULL_PTR  != request->P ) &&
        ( PKA_NULL_PTR  != request->Q ) &&
        ( PKA_NULL_PTR  != request->Dp ) &&
        ( PKA_NULL_PTR  != request->Dq ) &&
        ( PKA_NULL_PTR  != request->Qinv ) &&
        ( PKA_NULL_PTR  != request->Input ) &&
        ( PKA_NULL_PTR  != request->Output ) &&
        ( PKA_REQUEST_OK == sizeState )    )
    {
        const pka_DataCnt_t halfWordCount = Pka_Calc_WordCount( request->OperandSize );
        const pka_DataCnt_t fullSize       = (pka_DataCnt_t)( (uint32_t)request->OperandSize * PKA_DOUBLE_FACTOR );
        const pka_DataCnt_t fullWordCount  = Pka_Calc_WordCount( fullSize );

        pka_Runtime.ModuleState = PKA_STATE_BUSY;
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_OPERAND_LEN   , Pka_Calc_Bits( fullSize ) );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_RSACRT_DP     , request->Dp  , request->OperandSize, halfWordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_RSACRT_DQ     , request->Dq  , request->OperandSize, halfWordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_RSACRT_QINV   , request->Qinv, request->OperandSize, halfWordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_RSACRT_P      , request->P   , request->OperandSize, halfWordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_RSACRT_Q      , request->Q   , request->OperandSize, halfWordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_RSACRT_OPERAND_A, request->Input, fullSize           , fullWordCount );

        {
            const pka_RegRunResult_t runResult = Pka_Reg_Run( PKA_MODE_RSA_CRT_EXP );

            Pka_Finish_Operation( runResult, PKA_RESULT_OK, &retState );

            if( PKA_REQUEST_OK == retState )
            {
                (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_RSACRT_RESULT, request->Output, fullSize, fullWordCount );
            }
            else
            {
                /* Hardware error, result buffer is not written */
            }
        }
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }
#else
    (void)request;
#endif /* PKA */

    return ( retState );
}

/* ------------------------------ Elliptic curves ------------------------------ */

/**
 * \brief ECC scalar multiplication: result = scalar * point (RM, Table 426, MODE 0x20,
 *        side-channel protected - always used for a secret scalar per the README).
 */
pka_RequestState_t Pka_Set_EccScalarMul( const pka_Curve_t * const curve,
                                         const pka_Data_t * const scalar,
                                         const pka_EccPoint_t * const point,
                                         pka_EccPoint_t * const result )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    const pka_RequestState_t readyState = Pka_Check_Ready();
    pka_RequestState_t sizeState = PKA_REQUEST_ERROR;

    if( PKA_NULL_PTR != curve )
    {
        sizeState = Pka_Check_OperandSize( curve->SizeBytes, (pka_Bits_t)PKA_MAX_ECC_OPERAND_BITS );
    }
    else
    {
        sizeState = PKA_REQUEST_ERROR;
    }

    if( ( PKA_REQUEST_OK == readyState ) &&
        ( PKA_NULL_PTR  != curve ) &&
        ( PKA_NULL_PTR  != scalar ) &&
        ( PKA_NULL_PTR  != point ) &&
        ( PKA_NULL_PTR  != point->X ) &&
        ( PKA_NULL_PTR  != point->Y ) &&
        ( PKA_NULL_PTR  != result ) &&
        ( PKA_NULL_PTR  != result->X ) &&
        ( PKA_NULL_PTR  != result->Y ) &&
        ( PKA_NULL_PTR  != curve->Modulus ) &&
        ( PKA_NULL_PTR  != curve->A ) &&
        ( PKA_NULL_PTR  != curve->B ) &&
        ( PKA_NULL_PTR  != curve->Order ) &&
        ( PKA_REQUEST_OK == sizeState )    )
    {
        const pka_DataCnt_t wordCount = Pka_Calc_WordCount( curve->SizeBytes );
        const uint32_t        signRaw   = Pka_Calc_SignRaw( curve->ASign );

        pka_Runtime.ModuleState = PKA_STATE_BUSY;
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_ECCMUL_N_LEN, Pka_Calc_Bits( curve->SizeBytes ) );
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_ECCMUL_P_LEN, Pka_Calc_Bits( curve->SizeBytes ) );
        (void)Pka_Reg_Set_RamWord32( PKA_RAM_OFF_ECCMUL_A_SIGN, signRaw );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCMUL_A       , curve->A     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCMUL_B       , curve->B     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCMUL_MODULUS , curve->Modulus, curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCMUL_SCALAR_K, scalar       , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCMUL_POINT_X , point->X     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCMUL_POINT_Y , point->Y     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCMUL_ORDER_N , curve->Order , curve->SizeBytes, wordCount );

        {
            const pka_RegRunResult_t runResult = Pka_Reg_Run( PKA_MODE_ECC_SCALAR_MUL );

            if( PKA_REG_RUN_OK == runResult )
            {
                uint32_t statusCode = (uint32_t)PKA_STATUS_OK;

                (void)Pka_Reg_Read_Status( PKA_RAM_OFF_ECCMUL_ERROR, &statusCode );
                retState = Pka_Decode_EccScalarMul( statusCode );

                if( PKA_REQUEST_OK == retState )
                {
                    (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_ECCMUL_RESULT_X, result->X, curve->SizeBytes, wordCount );
                    (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_ECCMUL_RESULT_Y, result->Y, curve->SizeBytes, wordCount );
                }
                else
                {
                    /* Point at infinity or hardware fault, result buffer is not written */
                }
            }
            else
            {
                pka_Runtime.LastResult = PKA_RESULT_HARDWARE_ERROR;
                retState               = PKA_REQUEST_ERROR;
            }

            pka_Runtime.ModuleState = PKA_STATE_IDLE;

            if( PKA_NULL_PTR != pka_Runtime.CompleteCallback )
            {
                pka_Runtime.CompleteCallback( pka_Runtime.LastResult );
            }
            else
            {
                /* No callback registered */
            }
        }
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }
#else
    (void)curve;
    (void)scalar;
    (void)point;
    (void)result;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief Checks whether a point satisfies the curve equation (RM, Table 425, MODE 0x28).
 */
pka_RequestState_t Pka_Set_EccPointCheck( const pka_Curve_t * const curve,
                                          const pka_EccPoint_t * const point,
                                          pka_FunctionState_t * const onCurve )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    const pka_RequestState_t readyState = Pka_Check_Ready();
    pka_RequestState_t sizeState = PKA_REQUEST_ERROR;

    if( PKA_NULL_PTR != curve )
    {
        sizeState = Pka_Check_OperandSize( curve->SizeBytes, (pka_Bits_t)PKA_MAX_ECC_OPERAND_BITS );
    }
    else
    {
        sizeState = PKA_REQUEST_ERROR;
    }

    if( ( PKA_REQUEST_OK == readyState ) &&
        ( PKA_NULL_PTR  != curve ) &&
        ( PKA_NULL_PTR  != point ) &&
        ( PKA_NULL_PTR  != point->X ) &&
        ( PKA_NULL_PTR  != point->Y ) &&
        ( PKA_NULL_PTR  != onCurve ) &&
        ( PKA_NULL_PTR  != curve->Modulus ) &&
        ( PKA_NULL_PTR  != curve->A ) &&
        ( PKA_NULL_PTR  != curve->B ) &&
        ( PKA_REQUEST_OK == sizeState )    )
    {
        const pka_DataCnt_t wordCount = Pka_Calc_WordCount( curve->SizeBytes );
        const uint32_t        signRaw   = Pka_Calc_SignRaw( curve->ASign );

        pka_Runtime.ModuleState = PKA_STATE_BUSY;
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_MODULUS_LEN , Pka_Calc_Bits( curve->SizeBytes ) );
        (void)Pka_Reg_Set_RamWord32( PKA_RAM_OFF_PTCHK_A_SIGN, signRaw );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_PTCHK_A       , curve->A     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_PTCHK_B       , curve->B     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_PTCHK_MODULUS , curve->Modulus, curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_PTCHK_POINT_X , point->X     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_PTCHK_POINT_Y , point->Y     , curve->SizeBytes, wordCount );

        {
            const pka_RegRunResult_t runResult = Pka_Reg_Run( PKA_MODE_ECC_POINT_CHECK );

            if( PKA_REG_RUN_OK == runResult )
            {
                uint32_t statusCode = (uint32_t)PKA_STATUS_OK;

                (void)Pka_Reg_Read_Status( PKA_RAM_OFF_PTCHK_RESULT, &statusCode );
                retState = Pka_Decode_PointCheck( statusCode, onCurve );
            }
            else
            {
                pka_Runtime.LastResult = PKA_RESULT_HARDWARE_ERROR;
                retState               = PKA_REQUEST_ERROR;
            }

            pka_Runtime.ModuleState = PKA_STATE_IDLE;

            if( PKA_NULL_PTR != pka_Runtime.CompleteCallback )
            {
                pka_Runtime.CompleteCallback( pka_Runtime.LastResult );
            }
            else
            {
                /* No callback registered */
            }
        }
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }
#else
    (void)curve;
    (void)point;
    (void)onCurve;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief ECC complete addition: result = pointP + pointQ (RM, Table 432, MODE 0x23),
 *        chained with the projective to affine conversion (MODE 0x2F) so the caller
 *        always receives affine coordinates, matching \ref pka_EccPoint_t.
 */
pka_RequestState_t Pka_Set_EccAdd( const pka_Curve_t * const curve,
                                   const pka_EccPoint_t * const pointP,
                                   const pka_EccPoint_t * const pointQ,
                                   pka_EccPoint_t * const result )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    const pka_RequestState_t readyState = Pka_Check_Ready();
    pka_RequestState_t sizeState = PKA_REQUEST_ERROR;

    if( PKA_NULL_PTR != curve )
    {
        sizeState = Pka_Check_OperandSize( curve->SizeBytes, (pka_Bits_t)PKA_MAX_ECC_OPERAND_BITS );
    }
    else
    {
        sizeState = PKA_REQUEST_ERROR;
    }

    if( ( PKA_REQUEST_OK == readyState ) &&
        ( PKA_NULL_PTR  != curve ) &&
        ( PKA_NULL_PTR  != pointP ) &&
        ( PKA_NULL_PTR  != pointQ ) &&
        ( PKA_NULL_PTR  != pointP->X ) &&
        ( PKA_NULL_PTR  != pointP->Y ) &&
        ( PKA_NULL_PTR  != pointQ->X ) &&
        ( PKA_NULL_PTR  != pointQ->Y ) &&
        ( PKA_NULL_PTR  != result ) &&
        ( PKA_NULL_PTR  != result->X ) &&
        ( PKA_NULL_PTR  != result->Y ) &&
        ( PKA_NULL_PTR  != curve->Modulus ) &&
        ( PKA_NULL_PTR  != curve->A ) &&
        ( PKA_REQUEST_OK == sizeState )    )
    {
        const pka_DataCnt_t wordCount = Pka_Calc_WordCount( curve->SizeBytes );
        const uint32_t        signRaw   = Pka_Calc_SignRaw( curve->ASign );
        static const pka_Data_t affineZ[] = { 0x01u }; /* Affine input: Z = 1 (RM, 41.5.18) */

        pka_Runtime.ModuleState = PKA_STATE_BUSY;
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_ECCADD_P_LEN, Pka_Calc_Bits( curve->SizeBytes ) );
        (void)Pka_Reg_Set_RamWord32( PKA_RAM_OFF_ECCADD_A_SIGN, signRaw );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCADD_A      , curve->A      , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCADD_MODULUS, curve->Modulus, curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCADD_P_X    , pointP->X     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCADD_P_Y    , pointP->Y     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCADD_P_Z    , affineZ       , sizeof( affineZ ), wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCADD_Q_X    , pointQ->X     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCADD_Q_Y    , pointQ->Y     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECCADD_Q_Z    , affineZ       , sizeof( affineZ ), wordCount );

        {
            const pka_RegRunResult_t addRunResult = Pka_Reg_Run( PKA_MODE_ECC_COMPLETE_ADD );

            if( PKA_REG_RUN_OK == addRunResult )
            {
                /* RM Table 432 result offsets (0xD60/0xDB8/0xE10) and Table 434 projective
                 * input offsets are the same addresses, so the Jacobian sum is already in
                 * place for the projective-to-affine conversion; only the modulus length
                 * needs rewriting (0x408 is shared by both tables, already set above).
                 *
                 * \note Table 434 also lists an input Montgomery parameter R2 mod n
                 *       (RAM@0x4C8) whose necessity for this standalone (non-fast-mode)
                 *       MODE 0x2F call was not possible to confirm from the extracted
                 *       reference manual text; this should be verified before hardware use.
                 */
                {
                    const pka_RegRunResult_t toAffineResult = Pka_Reg_Run( PKA_MODE_ECC_PROJECTIVE_TO_AFFINE );

                    if( PKA_REG_RUN_OK == toAffineResult )
                    {
                        (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_PTCHK_POINT_X, result->X, curve->SizeBytes, wordCount );
                        (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_PTCHK_POINT_Y, result->Y, curve->SizeBytes, wordCount );
                        pka_Runtime.LastResult = PKA_RESULT_OK;
                        retState               = PKA_REQUEST_OK;
                    }
                    else
                    {
                        pka_Runtime.LastResult = PKA_RESULT_HARDWARE_ERROR;
                        retState               = PKA_REQUEST_ERROR;
                    }
                }
            }
            else
            {
                pka_Runtime.LastResult = PKA_RESULT_HARDWARE_ERROR;
                retState               = PKA_REQUEST_ERROR;
            }

            pka_Runtime.ModuleState = PKA_STATE_IDLE;

            if( PKA_NULL_PTR != pka_Runtime.CompleteCallback )
            {
                pka_Runtime.CompleteCallback( pka_Runtime.LastResult );
            }
            else
            {
                /* No callback registered */
            }
        }
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }
#else
    (void)curve;
    (void)pointP;
    (void)pointQ;
    (void)result;
#endif /* PKA */

    return ( retState );
}

/* ------------------------------------ ECDSA ---------------------------------- */

/**
 * \brief ECDSA signature generation (RM, Tables 427/428, MODE 0x24, side-channel protected).
 *
 * \note Upon \ref PKA_RESULT_HARDWARE_ERROR from this operation the RM (41.5.16)
 *       requires a new \p randomK and a repeated call, the failure is not necessarily
 *       a driver fault.
 */
pka_RequestState_t Pka_Set_EcdsaSign( const pka_Curve_t * const curve,
                                      const pka_Data_t * const privateKey,
                                      const pka_Data_t * const randomK,
                                      const pka_Data_t * const digest,
                                      pka_DataCnt_t digestSize,
                                      pka_EcdsaSignature_t * const signature )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    const pka_RequestState_t readyState = Pka_Check_Ready();
    pka_RequestState_t sizeState = PKA_REQUEST_ERROR;

    if( PKA_NULL_PTR != curve )
    {
        sizeState = Pka_Check_OperandSize( curve->SizeBytes, (pka_Bits_t)PKA_MAX_ECC_OPERAND_BITS );
    }
    else
    {
        sizeState = PKA_REQUEST_ERROR;
    }

    if( ( PKA_REQUEST_OK == readyState ) &&
        ( PKA_NULL_PTR  != curve ) &&
        ( PKA_NULL_PTR  != privateKey ) &&
        ( PKA_NULL_PTR  != randomK ) &&
        ( PKA_NULL_PTR  != digest ) &&
        ( PKA_NULL_PTR  != signature ) &&
        ( PKA_NULL_PTR  != signature->R ) &&
        ( PKA_NULL_PTR  != signature->S ) &&
        ( PKA_NULL_PTR  != curve->Modulus ) &&
        ( PKA_NULL_PTR  != curve->A ) &&
        ( PKA_NULL_PTR  != curve->B ) &&
        ( PKA_NULL_PTR  != curve->Gx ) &&
        ( PKA_NULL_PTR  != curve->Gy ) &&
        ( PKA_NULL_PTR  != curve->Order ) &&
        ( 0u             < digestSize ) &&
        ( PKA_REQUEST_OK == sizeState )    )
    {
        const pka_DataCnt_t wordCount = Pka_Calc_WordCount( curve->SizeBytes );
        const uint32_t        signRaw   = Pka_Calc_SignRaw( curve->ASign );

        pka_Runtime.ModuleState = PKA_STATE_BUSY;
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_ECDSASIGN_N_LEN, Pka_Calc_Bits( curve->SizeBytes ) );
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_ECDSASIGN_P_LEN, Pka_Calc_Bits( curve->SizeBytes ) );
        (void)Pka_Reg_Set_RamWord32( PKA_RAM_OFF_ECDSASIGN_A_SIGN, signRaw );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSASIGN_A         , curve->A     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSASIGN_B         , curve->B     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSASIGN_MODULUS   , curve->Modulus, curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSASIGN_K         , randomK      , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSASIGN_GX        , curve->Gx    , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSASIGN_GY        , curve->Gy    , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSASIGN_HASH      , digest       , digestSize      , wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSASIGN_PRIVATE_KEY, privateKey  , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSASIGN_ORDER_N   , curve->Order , curve->SizeBytes, wordCount );

        {
            const pka_RegRunResult_t runResult = Pka_Reg_Run( PKA_MODE_ECDSA_SIGN );

            if( PKA_REG_RUN_OK == runResult )
            {
                uint32_t statusCode = (uint32_t)PKA_STATUS_OK;

                (void)Pka_Reg_Read_Status( PKA_RAM_OFF_ECDSASIGN_ERROR, &statusCode );
                retState = Pka_Decode_EcdsaSign( statusCode );

                if( PKA_REQUEST_OK == retState )
                {
                    (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_ECDSASIGN_RESULT_R,
                                                signature->R,
                                                curve->SizeBytes,
                                                wordCount );
                    (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_ECDSASIGN_RESULT_S,
                                                signature->S,
                                                curve->SizeBytes,
                                                wordCount );
                }
                else
                {
                    /* Hardware / RNG fault, signature buffers are not written */
                }
            }
            else
            {
                pka_Runtime.LastResult = PKA_RESULT_HARDWARE_ERROR;
                retState               = PKA_REQUEST_ERROR;
            }

            pka_Runtime.ModuleState = PKA_STATE_IDLE;

            if( PKA_NULL_PTR != pka_Runtime.CompleteCallback )
            {
                pka_Runtime.CompleteCallback( pka_Runtime.LastResult );
            }
            else
            {
                /* No callback registered */
            }
        }
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }
#else
    (void)curve;
    (void)privateKey;
    (void)randomK;
    (void)digest;
    (void)digestSize;
    (void)signature;
#endif /* PKA */

    return ( retState );
}


/**
 * \brief ECDSA signature verification (RM, Tables 430/431, MODE 0x26).
 *
 * \note Table 430 has no curve coefficient `b` field (unlike the sign / scalar
 *       multiplication / point check tables) - only `a` is written. The
 *       `PKA_RAM_OFF_ECDSAVRFY_*` constants (\ref Pka.h) were re-extracted
 *       from RM0481 with `pdftotext` plain mode (without `-layout`) after the
 *       first pass of this file (layout mode) had garbled the table columns.
 *       Mode 0x26 is the only operation available on the devices restricted to
 *       the PKA limited mode (RM, section 41.3).
 */
pka_RequestState_t Pka_Set_EcdsaVerify( const pka_Curve_t * const curve,
                                        const pka_EccPoint_t * const publicKey,
                                        const pka_EcdsaSignature_t * const signature,
                                        const pka_Data_t * const digest,
                                        pka_DataCnt_t digestSize )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

#if defined(PKA)
    const pka_RequestState_t readyState = Pka_Check_Ready();
    pka_RequestState_t sizeState = PKA_REQUEST_ERROR;

    if( PKA_NULL_PTR != curve )
    {
        sizeState = Pka_Check_OperandSize( curve->SizeBytes, (pka_Bits_t)PKA_MAX_ECC_OPERAND_BITS );
    }
    else
    {
        sizeState = PKA_REQUEST_ERROR;
    }

    if( ( PKA_REQUEST_OK == readyState ) &&
        ( PKA_NULL_PTR  != curve ) &&
        ( PKA_NULL_PTR  != publicKey ) &&
        ( PKA_NULL_PTR  != publicKey->X ) &&
        ( PKA_NULL_PTR  != publicKey->Y ) &&
        ( PKA_NULL_PTR  != signature ) &&
        ( PKA_NULL_PTR  != signature->R ) &&
        ( PKA_NULL_PTR  != signature->S ) &&
        ( PKA_NULL_PTR  != digest ) &&
        ( PKA_NULL_PTR  != curve->Modulus ) &&
        ( PKA_NULL_PTR  != curve->A ) &&
        ( PKA_NULL_PTR  != curve->B ) &&
        ( PKA_NULL_PTR  != curve->Gx ) &&
        ( PKA_NULL_PTR  != curve->Gy ) &&
        ( PKA_NULL_PTR  != curve->Order ) &&
        ( 0u             < digestSize ) &&
        ( PKA_REQUEST_OK == sizeState )    )
    {
        const pka_DataCnt_t wordCount = Pka_Calc_WordCount( curve->SizeBytes );
        const uint32_t        signRaw   = Pka_Calc_SignRaw( curve->ASign );

        pka_Runtime.ModuleState = PKA_STATE_BUSY;
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_ECDSAVRFY_N_LEN, Pka_Calc_Bits( curve->SizeBytes ) );
        (void)Pka_Reg_Write_Length ( PKA_RAM_OFF_ECDSAVRFY_P_LEN, Pka_Calc_Bits( curve->SizeBytes ) );
        (void)Pka_Reg_Set_RamWord32( PKA_RAM_OFF_ECDSAVRFY_A_SIGN, signRaw );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSAVRFY_A      , curve->A      , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSAVRFY_MODULUS, curve->Modulus, curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSAVRFY_GX     , curve->Gx     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSAVRFY_GY     , curve->Gy     , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSAVRFY_QX     , publicKey->X  , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSAVRFY_QY     , publicKey->Y  , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSAVRFY_SIGN_R , signature->R  , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSAVRFY_SIGN_S , signature->S  , curve->SizeBytes, wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSAVRFY_HASH   , digest        , digestSize      , wordCount );
        (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_ECDSAVRFY_ORDER_N, curve->Order  , curve->SizeBytes, wordCount );

        {
            const pka_RegRunResult_t runResult = Pka_Reg_Run( PKA_MODE_ECDSA_VERIFY );

            if( PKA_REG_RUN_OK == runResult )
            {
                uint32_t statusCode = (uint32_t)PKA_STATUS_OK;

                (void)Pka_Reg_Read_Status( PKA_RAM_OFF_ECDSAVRFY_RESULT, &statusCode );
                retState = Pka_Decode_EcdsaVerify( statusCode );
            }
            else
            {
                pka_Runtime.LastResult = PKA_RESULT_HARDWARE_ERROR;
                retState               = PKA_REQUEST_ERROR;
            }

            pka_Runtime.ModuleState = PKA_STATE_IDLE;

            if( PKA_NULL_PTR != pka_Runtime.CompleteCallback )
            {
                pka_Runtime.CompleteCallback( pka_Runtime.LastResult );
            }
            else
            {
                /* No callback registered */
            }
        }
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }
#else
    (void)curve;
    (void)publicKey;
    (void)signature;
    (void)digest;
    (void)digestSize;
#endif /* PKA */

    return ( retState );
}

/* =========================== LOCAL FUNCTIONS ============================== */

#if defined(PKA)

/**
 * \brief Checks that the module is initialized and not running another operation.
 *
 * \return \ref PKA_REQUEST_OK if a new operation can be started, otherwise \ref PKA_REQUEST_ERROR.
 */
static pka_RequestState_t Pka_Check_Ready( void )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

    if( ( PKA_FUNCTION_ACTIVE == pka_Runtime.InitState ) &&
        ( PKA_STATE_IDLE      == pka_Runtime.ModuleState )    )
    {
        retState = PKA_REQUEST_OK;
    }
    else
    {
        /* Not initialized or an operation is already running */
        retState = PKA_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Computes the PKA 64-bit word count (ROS / EOS, zero guard word included,
 *        RM section 41.5.1) for an operand of \p byteSize bytes.
 */
static pka_DataCnt_t Pka_Calc_WordCount( pka_DataCnt_t byteSize )
{
    const uint32_t bits = ( (uint32_t)byteSize * PKA_BITS_PER_BYTE );

    return ( (pka_DataCnt_t)( ( bits / PKA_WORD_BITS ) + 1u ) );
}


/**
 * \brief Converts an operand byte length to the bit length the PKA length fields expect.
 */
static pka_Bits_t Pka_Calc_Bits( pka_DataCnt_t byteSize )
{
    return ( (pka_Bits_t)( (uint32_t)byteSize * PKA_BITS_PER_BYTE ) );
}


/**
 * \brief Validates a non-zero operand size against the device limit.
 */
static pka_RequestState_t Pka_Check_OperandSize( pka_DataCnt_t byteSize, pka_Bits_t maxBits )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;
    const uint32_t        bits     = ( (uint32_t)byteSize * PKA_BITS_PER_BYTE );

    if( ( 0u                != byteSize ) &&
        ( (uint32_t)maxBits >= bits     )    )
    {
        retState = PKA_REQUEST_OK;
    }
    else
    {
        retState = PKA_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Converts the public sign enumeration to the raw PKA_RAM sign bit (RM 41.6.1).
 */
static uint32_t Pka_Calc_SignRaw( pka_Sign_t sign )
{
    uint32_t retRaw = PKA_RAM_SIGN_POSITIVE_RAW;

    if( PKA_SIGN_NEGATIVE == sign )
    {
        retRaw = PKA_RAM_SIGN_NEGATIVE_RAW;
    }
    else
    {
        retRaw = PKA_RAM_SIGN_POSITIVE_RAW;
    }

    return ( retRaw );
}


/**
 * \brief Finishes a simple (single status-less) operation: updates the module
 *        state, \ref pka_Runtime.LastResult and invokes the complete callback.
 *
 * \param runResult [in]:     Outcome of \ref Pka_Reg_Run
 * \param hwResult  [in]:     Result to report when \p runResult is \ref PKA_REG_RUN_OK
 * \param retState  [out]:    Request outcome returned to the caller of the Set_* function
 */
static void Pka_Finish_Operation( pka_RegRunResult_t runResult,
                                  pka_Result_t hwResult,
                                  pka_RequestState_t * const retState )
{
    if( PKA_REG_RUN_OK == runResult )
    {
        pka_Runtime.LastResult = hwResult;
        *retState              = PKA_REQUEST_OK;
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_HARDWARE_ERROR;
        *retState              = PKA_REQUEST_ERROR;
    }

    pka_Runtime.ModuleState = PKA_STATE_IDLE;

    if( PKA_NULL_PTR != pka_Runtime.CompleteCallback )
    {
        pka_Runtime.CompleteCallback( pka_Runtime.LastResult );
    }
    else
    {
        /* No callback registered */
    }
}


/**
 * \brief Shared implementation of \ref Pka_Set_ModExp and \ref Pka_Set_RsaExp
 *        (RM, Tables 415 and 417, MODE 0x00 / 0x03).
 */
static pka_RequestState_t Pka_Exec_ModExp( const pka_Data_t * const base,
                                           const pka_Data_t * const exponent,
                                           const pka_Data_t * const modulus,
                                           pka_DataCnt_t operandSize,
                                           pka_FunctionState_t secretExponent,
                                           pka_Data_t * const result )
{
    pka_RequestState_t         retState  = Pka_Check_Ready();
    const pka_RequestState_t   sizeState = Pka_Check_OperandSize( operandSize, (pka_Bits_t)PKA_MAX_RSA_OPERAND_BITS );

    if( ( PKA_REQUEST_OK == retState ) &&
        ( PKA_NULL_PTR  != base ) &&
        ( PKA_NULL_PTR  != exponent ) &&
        ( PKA_NULL_PTR  != modulus ) &&
        ( PKA_NULL_PTR  != result ) &&
        ( PKA_REQUEST_OK == sizeState )    )
    {
        const pka_DataCnt_t wordCount  = Pka_Calc_WordCount( operandSize );
        const pka_Bits_t      operandBits = Pka_Calc_Bits( operandSize );

        pka_Runtime.ModuleState = PKA_STATE_BUSY;
        (void)Pka_Reg_Write_Length( PKA_RAM_OFF_EXPONENT_LEN, operandBits );
        (void)Pka_Reg_Write_Length( PKA_RAM_OFF_OPERAND_LEN , operandBits );

        if( PKA_FUNCTION_ACTIVE == secretExponent )
        {
            (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODEXP_PROT_OPERAND_A, base    , operandSize, wordCount );
            (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODEXP_PROT_EXPONENT , exponent, operandSize, wordCount );
            (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODEXP_PROT_MODULUS  , modulus , operandSize, wordCount );

            {
                const pka_RegRunResult_t runResult = Pka_Reg_Run( PKA_MODE_MODEXP_PROTECTED );

                if( PKA_REG_RUN_OK == runResult )
                {
                    uint32_t statusCode = (uint32_t)PKA_STATUS_OK;

                    (void)Pka_Reg_Read_Status( PKA_RAM_OFF_MODEXP_PROT_ERROR, &statusCode );

                    if( (uint32_t)PKA_STATUS_OK == statusCode )
                    {
                        pka_Runtime.LastResult = PKA_RESULT_OK;
                        retState               = PKA_REQUEST_OK;
                        (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_MODEXP_PROT_RESULT, result, operandSize, wordCount );
                    }
                    else
                    {
                        pka_Runtime.LastResult = PKA_RESULT_HARDWARE_ERROR;
                        retState               = PKA_REQUEST_ERROR;
                    }
                }
                else
                {
                    pka_Runtime.LastResult = PKA_RESULT_HARDWARE_ERROR;
                    retState               = PKA_REQUEST_ERROR;
                }
            }
        }
        else
        {
            (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODEXP_OPERAND_A, base    , operandSize, wordCount );
            (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODEXP_EXPONENT , exponent, operandSize, wordCount );
            (void)Pka_Reg_Write_Operand( PKA_RAM_OFF_MODEXP_MODULUS  , modulus , operandSize, wordCount );

            {
                const pka_RegRunResult_t runResult = Pka_Reg_Run( PKA_MODE_MODEXP_MONTGOMERY_THEN_EXP );

                Pka_Finish_Operation( runResult, PKA_RESULT_OK, &retState );

                if( PKA_REQUEST_OK == retState )
                {
                    (void)Pka_Reg_Read_Operand( PKA_RAM_OFF_MODEXP_RESULT, result, operandSize, wordCount );
                }
                else
                {
                    /* Hardware error, result buffer is not written */
                }
            }
        }

        pka_Runtime.ModuleState = PKA_STATE_IDLE;

        if( ( PKA_FUNCTION_ACTIVE == secretExponent ) &&
            ( PKA_NULL_PTR        != pka_Runtime.CompleteCallback )    )
        {
            pka_Runtime.CompleteCallback( pka_Runtime.LastResult );
        }
        else
        {
            /* Normal mode already invoked the callback through Pka_Finish_Operation */
        }
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Maps the point-on-curve check status word (RM, Table 425) to the module result.
 */
static pka_RequestState_t Pka_Decode_PointCheck( uint32_t statusCode, pka_FunctionState_t * const onCurve )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

    if( (uint32_t)PKA_STATUS_OK == statusCode )
    {
        *onCurve                = PKA_FUNCTION_ACTIVE;
        pka_Runtime.LastResult  = PKA_RESULT_OK;
        retState                = PKA_REQUEST_OK;
    }
    else if( (uint32_t)PKA_STATUS_POINT_NOT_ON_CURVE_OR_FAIL == statusCode )
    {
        *onCurve                = PKA_FUNCTION_INACTIVE;
        pka_Runtime.LastResult  = PKA_RESULT_POINT_NOT_ON_CURVE;
        retState                = PKA_REQUEST_OK;
    }
    else
    {
        /* Coordinate not smaller than the modulus, or another hardware status */
        pka_Runtime.LastResult = PKA_RESULT_OPERAND_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Maps the ECDSA verification status word (RM, Table 431) to the module result.
 */
static pka_RequestState_t Pka_Decode_EcdsaVerify( uint32_t statusCode )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

    if( (uint32_t)PKA_STATUS_OK == statusCode )
    {
        pka_Runtime.LastResult = PKA_RESULT_OK;
        retState               = PKA_REQUEST_OK;
    }
    else if( (uint32_t)PKA_STATUS_POINT_NOT_ON_CURVE_OR_FAIL == statusCode )
    {
        pka_Runtime.LastResult = PKA_RESULT_SIGNATURE_INVALID;
        retState               = PKA_REQUEST_OK;
    }
    else
    {
        pka_Runtime.LastResult = PKA_RESULT_HARDWARE_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Maps the ECC scalar multiplication status word (RM, Table 426) to the module result.
 */
static pka_RequestState_t Pka_Decode_EccScalarMul( uint32_t statusCode )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

    if( (uint32_t)PKA_STATUS_OK == statusCode )
    {
        pka_Runtime.LastResult = PKA_RESULT_OK;
        retState               = PKA_REQUEST_OK;
    }
    else
    {
        /* Error output different from 0xD60D: hardware fault or an unexpected point at infinity */
        pka_Runtime.LastResult = PKA_RESULT_HARDWARE_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Maps the ECDSA sign status word (RM, Table 428) to the module result.
 */
static pka_RequestState_t Pka_Decode_EcdsaSign( uint32_t statusCode )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;

    if( (uint32_t)PKA_STATUS_OK == statusCode )
    {
        pka_Runtime.LastResult = PKA_RESULT_OK;
        retState               = PKA_REQUEST_OK;
    }
    else
    {
        /* Computation failed, or r = 0, or s = 0 (RM 41.5.16: retry with a new randomK) */
        pka_Runtime.LastResult = PKA_RESULT_HARDWARE_ERROR;
        retState               = PKA_REQUEST_ERROR;
    }

    return ( retState );
}

#endif /* PKA */
