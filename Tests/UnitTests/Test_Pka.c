/**
 * \author Mr.Nobody
 * \file Test_Pka.c
 * \ingroup Pka
 * \brief Unit tests of the public key accelerator (PKA) module.
 *
 * Pka.c checks the PKA peripheral in every function (STM32H503 has none and only returns the
 * error value), Pka_Reg.c and Pka_Curves.c hold the register access and the curves; every test
 * case is written once and runs on every line, with the STM32H503 body replaced by
 * `TEST_IGNORE_MESSAGE` (the pattern used by the Cec module tests), except
 * \ref Ut_Pka_NoPeripheral_EveryFunctionReturnsError which runs only there. RCC (peripheral
 * clock) and NVIC (interrupt line) are mocked by CMock, the PKA registers and RAM are emulated
 * by RegMem.
 *
 * A HW model (UtPka_HwModel, only compiled where PKA is defined) makes PKA_SR.INITOK follow
 * PKA_CR.EN and PKA_SR.PROCENDF follow PKA_CR.START, so \ref Pka_Reg_Set_Enable and
 * \ref Pka_Reg_Run see the hardware ready
 * on their first read instead of looping the full bounded timeout. The model does not compute
 * any cryptographic result (RegMem is plain memory): tests of the operations preset the PKA
 * RAM result area themselves and check that it is converted to the big-endian output buffer
 * correctly - the actual known-answer (RSA / ECDSA) correctness is proven on the target by
 * the integration tests, per the module README.
 *
 * \par Expected results
 * See the Doxygen block of every test case.
 */

/* ============================= INCLUDES =================================== */
#include "unity.h"                          /* Unity testing framework        */
#include "RegMem.h"                         /* Register memory emulation      */
#include "Pka_Port.h"                       /* Module under test              */
#include "Pka.h"                            /* MODE codes, RAM offsets        */
#include "Pka_Reg.h"                        /* Register / RAM access          */
#include "MockRcc_Port.h"                   /* RCC module mock                */
#include "MockNvic_Port.h"                  /* NVIC module mock                */
#include "Stm32.h"                          /* PKA registers definition       */
/* ============================= TYPEDEFS =================================== */

/* ======================= FORWARD DECLARATIONS ============================= */

static void UtPka_CompleteCallback( pka_Result_t result );
static void UtPka_Fill_Marker( pka_Data_t * const buffer, pka_DataCnt_t size, uint32_t marker );
#if defined(PKA)
static void UtPka_HwModel( void );
static void UtPka_Expect_InitPoll( void );
static void UtPka_Init_Poll( void );
#endif /* PKA */

/* ========================= SYMBOLIC CONSTANTS ============================= */

/** Expected version of the module */
#define UT_PKA_VERSION_MAJOR                ( 1u )
#define UT_PKA_VERSION_MINOR                ( 0u )
#define UT_PKA_VERSION_PATCH                ( 0u )

/** Interrupt priority used by the ISR mode tests */
#define UT_PKA_IRQ_PRIO                      ( 5u )

/** PKA_CR.MODE written together with EN by Pka_Init() (ECDSA verification, authorized on every line) */
#define UT_PKA_ENABLE_MODE_RAW               ( (uint32_t)PKA_MODE_ECDSA_VERIFY << PKA_CR_MODE_Pos )

/** Operand size (bytes) used by the modular arithmetic tests (128 bits) */
#define UT_PKA_OPERAND_SIZE                  ( 16u )

/** Byte width of one 32-bit PKA RAM register access */
#define UT_PKA_REG32_BYTES                   ( 4u )

/** Mask and bit shifts used by \ref UtPka_Fill_Marker to place a 32-bit marker as bytes */
#define UT_PKA_BYTE_MASK                      ( 0xFFu )
#define UT_PKA_RM_BYTE1_SHIFT                 ( 8u )
#define UT_PKA_RM_BYTE2_SHIFT                 ( 16u )
#define UT_PKA_RM_BYTE3_SHIFT                 ( 24u )

/** Byte offset of the second 32-bit register of a 64-bit RAM word (RM 41.5.1) */
#define UT_PKA_WORD_HIGH_REG_OFFSET          UT_PKA_REG32_BYTES

/** Byte offset of the third 32-bit register (second 64-bit word) of a RAM area */
#define UT_PKA_WORD1_LOW_REG_OFFSET          ( 2u * UT_PKA_REG32_BYTES )

/** Byte offset of the fourth 32-bit register (second 64-bit word, high part) */
#define UT_PKA_WORD1_HIGH_REG_OFFSET         ( 3u * UT_PKA_REG32_BYTES )

/** Word count of a 2-word (one data word + one zero guard word) RAM area */
#define UT_PKA_TWO_WORD_CNT                  ( 2u )

/** Word count of a 1-word RAM area */
#define UT_PKA_ONE_WORD_CNT                  ( 1u )

/** Byte count one word (8 bytes, RM 41.5.1) too long for \ref UT_PKA_ONE_WORD_CNT */
#define UT_PKA_OVERSIZE_OPERAND_BYTES        ( 9u )

/** Sentinel register value used to prove a rejected write left the register untouched */
#define UT_PKA_SENTINEL_REG_VALUE            ( 0xFFFFFFFFu )

/** Result buffer byte offset (from the end) of the 0xAABBCCDD result word, high byte */
#define UT_PKA_RESULT_AA_INDEX_OFFSET        ( 4u )

/** Result buffer byte offset (from the end) of the 0x11223344 result word, high byte */
#define UT_PKA_RESULT_11_INDEX_OFFSET        ( 8u )

/** Preset RAM result value used by the modular addition marshaling test */
#define UT_PKA_RESULT_WORD_LOW               ( 0xAABBCCDDu )
#define UT_PKA_RESULT_WORD_HIGH              ( 0x11223344u )

/** Big-endian bytes expected back from \ref UT_PKA_RESULT_WORD_LOW / _HIGH */
#define UT_PKA_RESULT_BYTE_DD                ( 0xDDu )
#define UT_PKA_RESULT_BYTE_AA                ( 0xAAu )
#define UT_PKA_RESULT_BYTE_11                ( 0x11u )

/** Expected little-endian RAM words of operand A (RM example, section 41.5.1) */
#define UT_PKA_OPERAND_A_WORD0_LOW           ( 0x0D0E0F10u )
#define UT_PKA_OPERAND_A_WORD0_HIGH          ( 0x090A0B0Cu )
#define UT_PKA_OPERAND_A_WORD1_LOW           ( 0x05060708u )
#define UT_PKA_OPERAND_A_WORD1_HIGH          ( 0x01020304u )

/** Single non-zero byte value used by the small curve / signature fixtures below */
#define UT_PKA_FIXTURE_BYTE_1                ( 0x01u )
#define UT_PKA_FIXTURE_BYTE_2                ( 0x02u )
#define UT_PKA_FIXTURE_BYTE_3                ( 0x03u )
#define UT_PKA_FIXTURE_BYTE_4                ( 0x04u )
#define UT_PKA_FIXTURE_BYTE_5                ( 0x05u )
#define UT_PKA_FIXTURE_MODULUS               ( 0x0Du )

/** Bits in one byte, used to convert the test operand size to the RM length fields */
#define UT_PKA_BITS_PER_BYTE                 ( 8u )

/** One distinct 32-bit marker per ECDSA verification operand (RM, Table 430), used to prove
 *  every operand lands at its own documented RAM offset and not at some other field's */
#define UT_PKA_MARKER_MODULUS                ( 0xAAAAAAAAu )
#define UT_PKA_MARKER_A                      ( 0xBBBBBBBBu )
#define UT_PKA_MARKER_GX                     ( 0xCCCCCCCCu )
#define UT_PKA_MARKER_GY                     ( 0xDDDDDDDDu )
#define UT_PKA_MARKER_QX                     ( 0xEEEEEEEEu )
#define UT_PKA_MARKER_QY                     ( 0x66666666u )
#define UT_PKA_MARKER_SIGN_R                 ( 0x11111111u )
#define UT_PKA_MARKER_SIGN_S                 ( 0x22222222u )
#define UT_PKA_MARKER_HASH                   ( 0x33333333u )
#define UT_PKA_MARKER_ORDER                  ( 0x44444444u )

/** RAM offsets of the ECDSA verification operands (RM0481, Table 430), copied here as
 *  literals independent of the module's own PKA_RAM_OFF_ECDSAVRFY_ constants (Pka.h) on
 *  purpose: reading back through the same macro the module writes through would pass
 *  even if that macro held the wrong value (which is exactly how the original offset
 *  bug went undetected). */
#define UT_PKA_RM_OFF_ECDSAVRFY_MODULUS       ( 0x4D0u )
#define UT_PKA_RM_OFF_ECDSAVRFY_A             ( 0x470u )
#define UT_PKA_RM_OFF_ECDSAVRFY_GX            ( 0x678u )
#define UT_PKA_RM_OFF_ECDSAVRFY_GY            ( 0x6D0u )
#define UT_PKA_RM_OFF_ECDSAVRFY_QX            ( 0x12F8u )
#define UT_PKA_RM_OFF_ECDSAVRFY_QY            ( 0x1350u )
#define UT_PKA_RM_OFF_ECDSAVRFY_SIGN_R        ( 0x10E0u )
#define UT_PKA_RM_OFF_ECDSAVRFY_SIGN_S        ( 0xC68u )
#define UT_PKA_RM_OFF_ECDSAVRFY_HASH          ( 0x13A8u )
#define UT_PKA_RM_OFF_ECDSAVRFY_ORDER_N       ( 0x1088u )

/** Big-endian 128-bit operand A (01..10) used by the modular addition marshaling test */
#define UT_PKA_OPERAND_A_BYTES \
    0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u, \
    0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu, 0x10u

/* ========================== EXPORTED VARIABLES ============================= */

/* =========================== LOCAL VARIABLES ============================== */

/** Count of calls of \ref UtPka_CompleteCallback */
static uint32_t     utPka_CallbackCnt;

/** Result passed to the last call of \ref UtPka_CompleteCallback */
static pka_Result_t utPka_CallbackResult;

/* ============================ TEST FIXTURE ================================ */

void setUp( void )
{
    TEST_ASSERT_EQUAL( REGMEM_REQUEST_OK, RegMem_Reset() );
#if defined(PKA)
    TEST_ASSERT_EQUAL( REGMEM_REQUEST_OK, RegMem_Set_ModelActive( UtPka_HwModel ) );
#endif /* PKA */

    utPka_CallbackCnt    = 0u;
    utPka_CallbackResult = PKA_RESULT_NONE;
}


void tearDown( void )
{
    /* Mocks are verified by the generated runner */
}

/* ========================== MODULE VERSION ================================ */

/**
 * \brief   Pka_Get_ModuleVersion() returns the version of the module.
 *
 * \par Expected results
 * - Version is 1.0.0 (Major 1, Minor 0, Patch 0), the same on every line (common function).
 */
void Ut_Pka_Get_ModuleVersion_ReturnsVersion( void )
{
    const pka_ModuleVersion_t version = Pka_Get_ModuleVersion();

    TEST_ASSERT_EQUAL_UINT8( UT_PKA_VERSION_MAJOR, version.Major );
    TEST_ASSERT_EQUAL_UINT8( UT_PKA_VERSION_MINOR, version.Minor );
    TEST_ASSERT_EQUAL_UINT8( UT_PKA_VERSION_PATCH, version.Patch );
}


/**
 * \brief   Pka_Task() never touches the mocks and always returns.
 *
 * \par Expected results
 * - No RCC / NVIC call is expected (every operation of this implementation finishes
 *   synchronously inside its own Set_* call, there is never a pending operation).
 */
void Ut_Pka_Task_NoPendingOperation_ReturnsImmediately( void )
{
    Pka_Task();
}

/* =========================== DEFAULT CONFIG ================================ */

/**
 * \brief   Pka_Get_DefaultConfig() fills the default configuration.
 *
 * \par Expected results
 * - PKA_REQUEST_OK, POLL transfer mode, no callbacks.
 * - NULL pointer: PKA_REQUEST_ERROR.
 */
void Ut_Pka_Get_DefaultConfig_ReturnsDefaults( void )
{
#if defined(PKA)
    pka_Config_t config;

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_DefaultConfig( &config ) );

    TEST_ASSERT_EQUAL( PKA_XFER_MODE_POLL, config.XferMode );
    TEST_ASSERT_NULL( config.CompleteCallback );
    TEST_ASSERT_NULL( config.ErrorCallback );

    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Get_DefaultConfig( NULL ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}

/* ============================ INITIALIZATION =============================== */

/**
 * \brief   Pka_Init() in POLL mode enables the clock and the PKA, no NVIC call.
 *
 * \par Expected results
 * - PKA_REQUEST_OK, PKA_CR.EN is set, no Nvic_* call (no mock expectation set up).
 * - PKA_CR.MODE holds the ECDSA verification (0x26), the only mode authorized with EN on every line
 *   (the limited mode lines raise OPERRF for any other mode, RM0481 PKA_CR.MODE).
 * - Pka_Get_State() reports PKA_STATE_IDLE.
 */
void Ut_Pka_Init_PollMode_EnablesClockAndPeripheral( void )
{
#if defined(PKA)
    pka_State_t state = PKA_STATE_UNINIT;

    UtPka_Init_Poll();

    TEST_ASSERT_EQUAL_UINT32( PKA_CR_EN, ( PKA->CR & PKA_CR_EN ) );
    TEST_ASSERT_EQUAL_UINT32( UT_PKA_ENABLE_MODE_RAW, ( PKA->CR & PKA_CR_MODE ) );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_State( &state ) );
    TEST_ASSERT_EQUAL( PKA_STATE_IDLE, state );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}


/**
 * \brief   Pka_Init() in ISR mode also configures the NVIC priority and activates the line.
 *
 * \par Expected results
 * - PKA_REQUEST_OK, Nvic_Set_PeriphIrq_Prio and Nvic_Set_PeriphIrq_Active called once
 *   with NVIC_PERIPH_IRQ_PKA, PKA_CR interrupt enable bits are set.
 */
void Ut_Pka_Init_IsrMode_ConfiguresNvic( void )
{
#if defined(PKA)
    pka_Config_t config;
    const uint32_t irqMask = ( PKA_CR_PROCENDIE | PKA_CR_OPERRIE | PKA_CR_ADDRERRIE | PKA_CR_RAMERRIE );

    (void)Pka_Get_DefaultConfig( &config );
    config.XferMode    = PKA_XFER_MODE_ISR;
    config.IrqPriority = (pka_IrqPrio_t)UT_PKA_IRQ_PRIO;

    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_PKA, RCC_REQUEST_OK );
    Nvic_Set_PeriphIrq_Prio_ExpectAndReturn( NVIC_PERIPH_IRQ_PKA, (nvic_IrqPrio_t)UT_PKA_IRQ_PRIO, NVIC_REQUEST_OK );
    Nvic_Set_PeriphIrq_Active_ExpectAndReturn( NVIC_PERIPH_IRQ_PKA, NVIC_REQUEST_OK );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Init( &config ) );
    TEST_ASSERT_EQUAL_UINT32( irqMask, ( PKA->CR & irqMask ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}


/**
 * \brief   Pka_Init() with a NULL configuration is rejected and rolled back (Deinit) like
 *          every other Init failure (RM 2.7: Init verifies itself, deinitializes on failure).
 *
 * \par Expected results
 * - PKA_REQUEST_ERROR, Deinit's Nvic_Set_PeriphIrq_Inactive and Rcc_Set_PeriphInactive are
 *   called, no Rcc_Set_PeriphActive call (the clock was never enabled).
 */
void Ut_Pka_Init_NullConfig_ReturnsErrorWithoutAccess( void )
{
#if defined(PKA)
    Nvic_Set_PeriphIrq_Inactive_ExpectAndReturn( NVIC_PERIPH_IRQ_PKA, NVIC_REQUEST_OK );
    Rcc_Set_PeriphInactive_ExpectAndReturn( RCC_PERIPH_PKA, RCC_REQUEST_OK );

    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Init( NULL ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}


/**
 * \brief   Pka_Init() rolls back (Deinit) when the clock could not be enabled.
 *
 * \par Expected results
 * - PKA_REQUEST_ERROR, Nvic_Set_PeriphIrq_Inactive and Rcc_Set_PeriphInactive called by
 *   the Deinit rollback, PKA_CR.EN stays clear.
 */
void Ut_Pka_Init_ClockFailure_RollsBackToUninit( void )
{
#if defined(PKA)
    pka_Config_t config;

    (void)Pka_Get_DefaultConfig( &config );

    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_PKA, RCC_REQUEST_ERROR );
    Nvic_Set_PeriphIrq_Inactive_ExpectAndReturn( NVIC_PERIPH_IRQ_PKA, NVIC_REQUEST_OK );
    Rcc_Set_PeriphInactive_ExpectAndReturn( RCC_PERIPH_PKA, RCC_REQUEST_OK );

    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Init( &config ) );
    TEST_ASSERT_EQUAL_UINT32( 0u, ( PKA->CR & PKA_CR_EN ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}


/**
 * \brief   Pka_Deinit() disables the interrupt, the peripheral and its clock.
 *
 * \par Expected results
 * - PKA_REQUEST_OK, Nvic_Set_PeriphIrq_Inactive and Rcc_Set_PeriphInactive called once,
 *   PKA_CR.EN is cleared, Pka_Get_State() reports PKA_STATE_UNINIT afterwards.
 */
void Ut_Pka_Deinit_DisablesPeripheralAndClock( void )
{
#if defined(PKA)
    pka_State_t state = PKA_STATE_IDLE;

    UtPka_Init_Poll();

    Nvic_Set_PeriphIrq_Inactive_ExpectAndReturn( NVIC_PERIPH_IRQ_PKA, NVIC_REQUEST_OK );
    Rcc_Set_PeriphInactive_ExpectAndReturn( RCC_PERIPH_PKA, RCC_REQUEST_OK );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Deinit() );
    TEST_ASSERT_EQUAL_UINT32( 0u, ( PKA->CR & PKA_CR_EN ) );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_State( &state ) );
    TEST_ASSERT_EQUAL( PKA_STATE_UNINIT, state );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}

/* ========================= CAPABILITY / LIMITS ============================== */

/**
 * \brief   Pka_Get_Capability() reports only the ECDSA verification on the lines with the PKA in the limited mode.
 *
 * \par Expected results
 * - H523, H543, H562, H563: PKA_OPERATION_ECDSA_VERIFY PKA_FUNCTION_ACTIVE, every other operation inactive.
 * - Every other line with PKA: every listed operation PKA_FUNCTION_ACTIVE.
 */
void Ut_Pka_Get_Capability_LimitedModeLines_OnlyVerify( void )
{
#if defined(PKA)
    pka_FunctionState_t verifyState = PKA_FUNCTION_INACTIVE;
    pka_FunctionState_t signState   = PKA_FUNCTION_INACTIVE;
    pka_FunctionState_t addState    = PKA_FUNCTION_INACTIVE;

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Capability( PKA_OPERATION_ECDSA_VERIFY, &verifyState ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Capability( PKA_OPERATION_ECDSA_SIGN, &signState ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Capability( PKA_OPERATION_MOD_ADD, &addState ) );

    TEST_ASSERT_EQUAL( PKA_FUNCTION_ACTIVE, verifyState );

#if defined( STM32H523xx ) || \
    defined( STM32H543xx ) || \
    defined( STM32H562xx ) || \
    defined( STM32H563xx )
    TEST_ASSERT_EQUAL( PKA_FUNCTION_INACTIVE, signState );
    TEST_ASSERT_EQUAL( PKA_FUNCTION_INACTIVE, addState );
#else
    TEST_ASSERT_EQUAL( PKA_FUNCTION_ACTIVE, signState );
    TEST_ASSERT_EQUAL( PKA_FUNCTION_ACTIVE, addState );
#endif /* limited mode lines */
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}


/**
 * \brief   Pka_Get_Capability() accepts a valid operation and rejects an invalid operation / NULL pointer.
 *
 * \par Expected results
 * - PKA_REQUEST_OK and PKA_FUNCTION_ACTIVE for PKA_OPERATION_ECDSA_VERIFY.
 * - PKA_REQUEST_ERROR for PKA_OPERATION_UNUSED and for a NULL output pointer.
 */
void Ut_Pka_Get_Capability_ValidAndInvalidOperation( void )
{
#if defined(PKA)
    pka_FunctionState_t supported = PKA_FUNCTION_INACTIVE;

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Capability( PKA_OPERATION_ECDSA_VERIFY, &supported ) );
    TEST_ASSERT_EQUAL( PKA_FUNCTION_ACTIVE, supported );

    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Get_Capability( PKA_OPERATION_UNUSED, &supported ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Get_Capability( PKA_OPERATION_ECDSA_VERIFY, NULL ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}


/**
 * \brief   Pka_Get_MaxOperandBits() returns the RM0481 section 41.2 limits.
 *
 * \par Expected results
 * - 4160 bits for PKA_OPERAND_TYPE_RSA, 640 bits for PKA_OPERAND_TYPE_ECC.
 * - PKA_REQUEST_ERROR for PKA_OPERAND_TYPE_UNUSED and for a NULL output pointer.
 */
void Ut_Pka_Get_MaxOperandBits_RsaAndEcc( void )
{
#if defined(PKA)
    pka_Bits_t maxBits = 0u;

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_MaxOperandBits( PKA_OPERAND_TYPE_RSA, &maxBits ) );
    TEST_ASSERT_EQUAL_UINT16( PKA_MAX_RSA_OPERAND_BITS, maxBits );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_MaxOperandBits( PKA_OPERAND_TYPE_ECC, &maxBits ) );
    TEST_ASSERT_EQUAL_UINT16( PKA_MAX_ECC_OPERAND_BITS, maxBits );

    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Get_MaxOperandBits( PKA_OPERAND_TYPE_UNUSED, &maxBits ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Get_MaxOperandBits( PKA_OPERAND_TYPE_RSA, NULL ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}


/**
 * \brief   Pka_Get_Result() fails before Pka_Init() and with a NULL pointer.
 *
 * \par Expected results
 * - PKA_REQUEST_ERROR for both calls, nothing is written.
 */
void Ut_Pka_Get_Result_NotInitialized_ReturnsError( void )
{
#if defined(PKA)
    pka_Result_t result = PKA_RESULT_OK;

    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Get_Result( &result ) );
    TEST_ASSERT_EQUAL( PKA_RESULT_OK, result );

    UtPka_Init_Poll();
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Get_Result( NULL ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}

/* =========================== MODULAR ADDITION ================================ */

/**
 * \brief   Pka_Set_ModAdd() rejects NULL pointers and an operand size over the device limit
 *          without touching the hardware.
 *
 * \par Expected results
 * - PKA_REQUEST_ERROR for every NULL operand, for operandSize 0 and for an operand size
 *   whose bit length is over PKA_MAX_RSA_OPERAND_BITS.
 * - PKA_CR.MODE stays at the mode written by Pka_Init() (no operation was started).
 */
void Ut_Pka_Set_ModAdd_InvalidParameters_ReturnsErrorWithoutAccess( void )
{
#if defined(PKA)
    pka_Data_t a[UT_PKA_OPERAND_SIZE]      = { 0 };
    pka_Data_t b[UT_PKA_OPERAND_SIZE]      = { 0 };
    pka_Data_t modulus[UT_PKA_OPERAND_SIZE] = { 0 };
    pka_Data_t result[UT_PKA_OPERAND_SIZE]  = { 0 };
    const pka_DataCnt_t oversizeBytes = (pka_DataCnt_t)( ( PKA_MAX_RSA_OPERAND_BITS / 8u ) + 1u );

    UtPka_Init_Poll();

    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR,
                       Pka_Set_ModAdd( NULL, b, modulus, UT_PKA_OPERAND_SIZE, result ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR,
                       Pka_Set_ModAdd( a, NULL, modulus, UT_PKA_OPERAND_SIZE, result ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR,
                       Pka_Set_ModAdd( a, b, NULL, UT_PKA_OPERAND_SIZE, result ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR,
                       Pka_Set_ModAdd( a, b, modulus, UT_PKA_OPERAND_SIZE, NULL ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Set_ModAdd( a, b, modulus, 0u, result ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR,
                       Pka_Set_ModAdd( a, b, modulus, oversizeBytes, result ) );

    TEST_ASSERT_EQUAL_UINT32( UT_PKA_ENABLE_MODE_RAW, ( PKA->CR & PKA_CR_MODE ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}


/**
 * \brief   Pka_Set_ModAdd() is rejected before Pka_Init().
 *
 * \par Expected results
 * - PKA_REQUEST_ERROR, PKA_CR is untouched.
 */
void Ut_Pka_Set_ModAdd_NotInitialized_ReturnsError( void )
{
#if defined(PKA)
    static const pka_Data_t a[UT_PKA_OPERAND_SIZE]      = { UT_PKA_FIXTURE_BYTE_1 };
    static const pka_Data_t b[UT_PKA_OPERAND_SIZE]      = { UT_PKA_FIXTURE_BYTE_1 };
    static const pka_Data_t modulus[UT_PKA_OPERAND_SIZE] = { UT_PKA_FIXTURE_BYTE_3 };
    pka_Data_t                result[UT_PKA_OPERAND_SIZE]  = { 0 };

    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR,
                       Pka_Set_ModAdd( a, b, modulus, UT_PKA_OPERAND_SIZE, result ) );
    TEST_ASSERT_EQUAL_UINT32( 0u, PKA->CR );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}


/**
 * \brief   Pka_Set_ModAdd() writes the operand length and the operands as little-endian
 *          64-bit words with the zero guard word, selects MODE 0x0E and reads the result
 *          back as a big-endian buffer (RM0481, Table 412).
 *
 * \par Expected results
 * - PKA_REQUEST_OK, Pka_Get_Result() reports PKA_RESULT_OK, the complete callback is
 *   invoked once with PKA_RESULT_OK.
 * - RAM@0x408 holds the operand length in bits, RAM@0xA50 holds operand A as a 3-word
 *   (128-bit + guard word) little-endian value, PKA_CR.MODE is PKA_MODE_MOD_ADD.
 * - The result buffer is the big-endian conversion of the words preset at RAM@0xE78.
 */
void Ut_Pka_Set_ModAdd_ValidOperands_WritesRamAndReadsResult( void )
{
#if defined(PKA)
    static const pka_Data_t a[UT_PKA_OPERAND_SIZE] = { UT_PKA_OPERAND_A_BYTES };
    pka_Data_t                b[UT_PKA_OPERAND_SIZE]       = { 0 };
    pka_Data_t                modulus[UT_PKA_OPERAND_SIZE] = { 0 };
    pka_Data_t                result[UT_PKA_OPERAND_SIZE]  = { 0 };
    pka_Config_t              config;
    pka_Result_t              getResult = PKA_RESULT_NONE;
    const pka_DataCnt_t       wordCount = (pka_DataCnt_t)( ( ( (uint32_t)UT_PKA_OPERAND_SIZE *
                                                              UT_PKA_BITS_PER_BYTE ) / PKA_WORD_BITS ) + 1u );

    (void)Pka_Get_DefaultConfig( &config );
    config.CompleteCallback = UtPka_CompleteCallback;
    UtPka_Expect_InitPoll();
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Init( &config ) );

    /* Preset the result area (RAM@0xE78) the module reads back after the "operation" */
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Reg_Set_RamWord32( PKA_RAM_OFF_MODADD_RESULT, UT_PKA_RESULT_WORD_LOW ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Reg_Set_RamWord32( ( PKA_RAM_OFF_MODADD_RESULT + UT_PKA_WORD_HIGH_REG_OFFSET ),
                                              UT_PKA_RESULT_WORD_HIGH ) );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Set_ModAdd( a, b, modulus, UT_PKA_OPERAND_SIZE, result ) );

    /* Operand length field (bits, one word, RM section 41.5.1) */
    TEST_ASSERT_EQUAL_UINT32( (uint32_t)UT_PKA_OPERAND_SIZE * UT_PKA_BITS_PER_BYTE,
                              PKA->RAM[( PKA_RAM_OFF_OPERAND_LEN - PKA_RAM_BASE_OFFSET ) / UT_PKA_REG32_BYTES] );

    /* Operand A (big-endian 01..10) as little-endian words, least significant word first:
     * word0 low/high = the last 8 bytes (09..10), word1 low/high = the first 8 bytes (01..08),
     * word2 (guard word, wordCount = 3) stays zero. */
    TEST_ASSERT_EQUAL_UINT32( UT_PKA_OPERAND_A_WORD0_LOW,
                              PKA->RAM[( PKA_RAM_OFF_MODADD_OPERAND_A - PKA_RAM_BASE_OFFSET ) / UT_PKA_REG32_BYTES] );
    TEST_ASSERT_EQUAL_UINT32( UT_PKA_OPERAND_A_WORD0_HIGH,
                              PKA->RAM[( ( PKA_RAM_OFF_MODADD_OPERAND_A + UT_PKA_WORD_HIGH_REG_OFFSET )
                                        - PKA_RAM_BASE_OFFSET ) / UT_PKA_REG32_BYTES] );
    TEST_ASSERT_EQUAL_UINT32( UT_PKA_OPERAND_A_WORD1_LOW,
                              PKA->RAM[( ( PKA_RAM_OFF_MODADD_OPERAND_A + UT_PKA_WORD1_LOW_REG_OFFSET )
                                        - PKA_RAM_BASE_OFFSET ) / UT_PKA_REG32_BYTES] );
    TEST_ASSERT_EQUAL_UINT32( UT_PKA_OPERAND_A_WORD1_HIGH,
                              PKA->RAM[( ( PKA_RAM_OFF_MODADD_OPERAND_A + UT_PKA_WORD1_HIGH_REG_OFFSET )
                                        - PKA_RAM_BASE_OFFSET ) / UT_PKA_REG32_BYTES] );
    TEST_ASSERT_EQUAL_UINT32( 0u,
                              PKA->RAM[( ( PKA_RAM_OFF_MODADD_OPERAND_A + ( wordCount - 1u ) * PKA_WORD_BYTES )
                                        - PKA_RAM_BASE_OFFSET ) / UT_PKA_REG32_BYTES] );

    TEST_ASSERT_EQUAL_UINT32( PKA_CR_MODE_1 | PKA_CR_MODE_2 | PKA_CR_MODE_3,
                              ( PKA->CR & PKA_CR_MODE ) );

    /* Result words preset above (0xAABBCCDD, 0x11223344) decoded back to big-endian bytes */
    TEST_ASSERT_EQUAL_HEX8( UT_PKA_RESULT_BYTE_DD, result[UT_PKA_OPERAND_SIZE - 1u] );
    TEST_ASSERT_EQUAL_HEX8( UT_PKA_RESULT_BYTE_AA, result[UT_PKA_OPERAND_SIZE - UT_PKA_RESULT_AA_INDEX_OFFSET] );
    TEST_ASSERT_EQUAL_HEX8( UT_PKA_RESULT_BYTE_11, result[UT_PKA_OPERAND_SIZE - UT_PKA_RESULT_11_INDEX_OFFSET] );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Result( &getResult ) );
    TEST_ASSERT_EQUAL( PKA_RESULT_OK, getResult );

    TEST_ASSERT_EQUAL_UINT32( 1u, utPka_CallbackCnt );
    TEST_ASSERT_EQUAL( PKA_RESULT_OK, utPka_CallbackResult );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}

/* ======================= MODULAR EXPONENTIATION (MODE SELECTION) ============== */

/**
 * \brief   Pka_Set_ModExp() selects the protected MODE (0x03) for a secret exponent and
 *          the normal MODE (0x00) otherwise (RM0481, Tables 415 / 417).
 *
 * \par Expected results
 * - PKA_CR.MODE equals PKA_MODE_MODEXP_PROTECTED after the secret-exponent call.
 * - PKA_CR.MODE equals PKA_MODE_MODEXP_MONTGOMERY_THEN_EXP (0) after the public call.
 */
void Ut_Pka_Set_ModExp_SecretFlag_SelectsProtectedMode( void )
{
#if defined(PKA)
    static const pka_Data_t base[UT_PKA_OPERAND_SIZE]    = { UT_PKA_FIXTURE_BYTE_2 };
    static const pka_Data_t exponent[UT_PKA_OPERAND_SIZE] = { UT_PKA_FIXTURE_BYTE_3 };
    static const pka_Data_t modulus[UT_PKA_OPERAND_SIZE]  = { UT_PKA_FIXTURE_MODULUS };
    pka_Data_t                result[UT_PKA_OPERAND_SIZE]   = { 0 };

    UtPka_Init_Poll();

    /* Protected mode reports its own success code at a dedicated RAM status word (Table 417) */
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Reg_Set_RamWord32( PKA_RAM_OFF_MODEXP_PROT_ERROR, (uint32_t)PKA_STATUS_OK ) );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Set_ModExp( base,
                                       exponent,
                                       modulus,
                                       UT_PKA_OPERAND_SIZE,
                                       PKA_FUNCTION_ACTIVE,
                                       result ) );
    TEST_ASSERT_EQUAL_UINT32( (uint32_t)PKA_MODE_MODEXP_PROTECTED << PKA_CR_MODE_Pos,
                              ( PKA->CR & PKA_CR_MODE ) );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Set_ModExp( base,
                                       exponent,
                                       modulus,
                                       UT_PKA_OPERAND_SIZE,
                                       PKA_FUNCTION_INACTIVE,
                                       result ) );
    TEST_ASSERT_EQUAL_UINT32( 0u, ( PKA->CR & PKA_CR_MODE ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}

/* =========================== POINT ON CURVE CHECK ============================= */

/**
 * \brief   Pka_Set_EccPointCheck() maps the hardware status word to the public result
 *          (RM0481, Table 425: 0xD60D on curve, 0xA3B7 not on curve).
 *
 * \par Expected results
 * - Status 0xD60D: PKA_REQUEST_OK, onCurve PKA_FUNCTION_ACTIVE, Get_Result() PKA_RESULT_OK.
 * - Status 0xA3B7: PKA_REQUEST_OK, onCurve PKA_FUNCTION_INACTIVE, Get_Result()
 *   PKA_RESULT_POINT_NOT_ON_CURVE (not a driver error, per the README).
 */
void Ut_Pka_Set_EccPointCheck_StatusMapping( void )
{
#if defined(PKA)
    pka_Data_t modulusBytes[UT_PKA_OPERAND_SIZE] = { UT_PKA_FIXTURE_MODULUS };
    pka_Data_t aBytes[UT_PKA_OPERAND_SIZE]       = { UT_PKA_FIXTURE_BYTE_1 };
    pka_Data_t bBytes[UT_PKA_OPERAND_SIZE]       = { UT_PKA_FIXTURE_BYTE_1 };
    pka_Data_t gxBytes[UT_PKA_OPERAND_SIZE]      = { UT_PKA_FIXTURE_BYTE_1 };
    pka_Data_t gyBytes[UT_PKA_OPERAND_SIZE]      = { UT_PKA_FIXTURE_BYTE_1 };
    pka_Data_t orderBytes[UT_PKA_OPERAND_SIZE]   = { UT_PKA_FIXTURE_BYTE_1 };
    pka_Data_t pointX[UT_PKA_OPERAND_SIZE]       = { UT_PKA_FIXTURE_BYTE_2 };
    pka_Data_t pointY[UT_PKA_OPERAND_SIZE]       = { UT_PKA_FIXTURE_BYTE_2 };
    const pka_Curve_t curve =
    {
        .Modulus = modulusBytes, .A = aBytes, .ASign = PKA_SIGN_POSITIVE, .B = bBytes,
        .Gx = gxBytes, .Gy = gyBytes, .Order = orderBytes, .SizeBytes = UT_PKA_OPERAND_SIZE
    };
    const pka_EccPoint_t point = { .X = pointX, .Y = pointY };
    pka_FunctionState_t onCurve = PKA_FUNCTION_INACTIVE;
    pka_Result_t          getResult = PKA_RESULT_NONE;

    UtPka_Init_Poll();

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Reg_Set_RamWord32( PKA_RAM_OFF_PTCHK_RESULT, (uint32_t)PKA_STATUS_OK ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Set_EccPointCheck( &curve, &point, &onCurve ) );
    TEST_ASSERT_EQUAL( PKA_FUNCTION_ACTIVE, onCurve );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Result( &getResult ) );
    TEST_ASSERT_EQUAL( PKA_RESULT_OK, getResult );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Reg_Set_RamWord32( PKA_RAM_OFF_PTCHK_RESULT,
                                              (uint32_t)PKA_STATUS_POINT_NOT_ON_CURVE_OR_FAIL ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Set_EccPointCheck( &curve, &point, &onCurve ) );
    TEST_ASSERT_EQUAL( PKA_FUNCTION_INACTIVE, onCurve );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Result( &getResult ) );
    TEST_ASSERT_EQUAL( PKA_RESULT_POINT_NOT_ON_CURVE, getResult );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}

/* ============================= ECDSA VERIFY =================================== */

/**
 * \brief   Pka_Set_EcdsaVerify() maps an invalid-signature status to PKA_RESULT_SIGNATURE_INVALID,
 *          which is a successful request (RM0481, Table 431 / README rule 3).
 *
 * \par Expected results
 * - PKA_REQUEST_OK (the verification itself ran correctly).
 * - Pka_Get_Result() reports PKA_RESULT_SIGNATURE_INVALID, not a hardware error.
 */
void Ut_Pka_Set_EcdsaVerify_InvalidSignature_IsNotADriverError( void )
{
#if defined(PKA)
    pka_Data_t modulusBytes[UT_PKA_OPERAND_SIZE] = { UT_PKA_FIXTURE_MODULUS };
    pka_Data_t aBytes[UT_PKA_OPERAND_SIZE]       = { UT_PKA_FIXTURE_BYTE_1 };
    pka_Data_t bBytes[UT_PKA_OPERAND_SIZE]       = { UT_PKA_FIXTURE_BYTE_1 };
    pka_Data_t gxBytes[UT_PKA_OPERAND_SIZE]      = { UT_PKA_FIXTURE_BYTE_1 };
    pka_Data_t gyBytes[UT_PKA_OPERAND_SIZE]      = { UT_PKA_FIXTURE_BYTE_1 };
    pka_Data_t orderBytes[UT_PKA_OPERAND_SIZE]   = { UT_PKA_FIXTURE_BYTE_1 };
    pka_Data_t qx[UT_PKA_OPERAND_SIZE]           = { UT_PKA_FIXTURE_BYTE_2 };
    pka_Data_t qy[UT_PKA_OPERAND_SIZE]           = { UT_PKA_FIXTURE_BYTE_2 };
    pka_Data_t sigR[UT_PKA_OPERAND_SIZE]         = { UT_PKA_FIXTURE_BYTE_3 };
    pka_Data_t sigS[UT_PKA_OPERAND_SIZE]         = { UT_PKA_FIXTURE_BYTE_4 };
    pka_Data_t digest[UT_PKA_OPERAND_SIZE]       = { UT_PKA_FIXTURE_BYTE_5 };
    const pka_Curve_t curve =
    {
        .Modulus = modulusBytes, .A = aBytes, .ASign = PKA_SIGN_POSITIVE, .B = bBytes,
        .Gx = gxBytes, .Gy = gyBytes, .Order = orderBytes, .SizeBytes = UT_PKA_OPERAND_SIZE
    };
    const pka_EccPoint_t      publicKey = { .X = qx, .Y = qy };
    const pka_EcdsaSignature_t signature = { .R = sigR, .S = sigS };
    pka_Result_t                getResult = PKA_RESULT_NONE;

    UtPka_Init_Poll();

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Reg_Set_RamWord32( PKA_RAM_OFF_ECDSAVRFY_RESULT,
                                              (uint32_t)PKA_STATUS_POINT_NOT_ON_CURVE_OR_FAIL ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Set_EcdsaVerify( &curve, &publicKey, &signature, digest, UT_PKA_OPERAND_SIZE ) );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_Result( &getResult ) );
    TEST_ASSERT_EQUAL( PKA_RESULT_SIGNATURE_INVALID, getResult );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}


/**
 * \brief   Pka_Set_EcdsaVerify() writes every operand at its own documented RAM offset
 *          (RM0481, Table 430) and not at another field's offset.
 *
 * \details Every operand gets a distinct marker (\ref UtPka_Fill_Marker) in its last 4
 *          bytes; the test reads PKA RAM back directly at each of the UT_PKA_RM_OFF_ECDSAVRFY_
 *          constants above and checks the matching marker, so two fields swapped (or a wrong offset
 *          pointing at another field's area) are caught by a mismatch, not just a missed
 *          result - the class of bug a pure status-code / final-result check cannot see.
 *
 * \par Expected results
 * - Every PKA RAM register read back at the documented offset equals the operand's own
 *   marker.
 */
void Ut_Pka_Set_EcdsaVerify_WritesEveryOperandAtDocumentedOffset( void )
{
#if defined(PKA)
    pka_Data_t modulusBytes[UT_PKA_OPERAND_SIZE];
    pka_Data_t aBytes[UT_PKA_OPERAND_SIZE];
    pka_Data_t gxBytes[UT_PKA_OPERAND_SIZE];
    pka_Data_t gyBytes[UT_PKA_OPERAND_SIZE];
    pka_Data_t orderBytes[UT_PKA_OPERAND_SIZE];
    pka_Data_t qx[UT_PKA_OPERAND_SIZE];
    pka_Data_t qy[UT_PKA_OPERAND_SIZE];
    pka_Data_t sigR[UT_PKA_OPERAND_SIZE];
    pka_Data_t sigS[UT_PKA_OPERAND_SIZE];
    pka_Data_t digest[UT_PKA_OPERAND_SIZE];
    const pka_Curve_t curve =
    {
        .Modulus = modulusBytes, .A = aBytes, .ASign = PKA_SIGN_POSITIVE, .B = aBytes,
        .Gx = gxBytes, .Gy = gyBytes, .Order = orderBytes, .SizeBytes = UT_PKA_OPERAND_SIZE
    };
    const pka_EccPoint_t      publicKey = { .X = qx, .Y = qy };
    const pka_EcdsaSignature_t signature = { .R = sigR, .S = sigS };
    uint32_t                    readBack  = 0u;

    UtPka_Fill_Marker( modulusBytes, UT_PKA_OPERAND_SIZE, UT_PKA_MARKER_MODULUS );
    UtPka_Fill_Marker( aBytes      , UT_PKA_OPERAND_SIZE, UT_PKA_MARKER_A );
    UtPka_Fill_Marker( gxBytes     , UT_PKA_OPERAND_SIZE, UT_PKA_MARKER_GX );
    UtPka_Fill_Marker( gyBytes     , UT_PKA_OPERAND_SIZE, UT_PKA_MARKER_GY );
    UtPka_Fill_Marker( orderBytes  , UT_PKA_OPERAND_SIZE, UT_PKA_MARKER_ORDER );
    UtPka_Fill_Marker( qx          , UT_PKA_OPERAND_SIZE, UT_PKA_MARKER_QX );
    UtPka_Fill_Marker( qy          , UT_PKA_OPERAND_SIZE, UT_PKA_MARKER_QY );
    UtPka_Fill_Marker( sigR        , UT_PKA_OPERAND_SIZE, UT_PKA_MARKER_SIGN_R );
    UtPka_Fill_Marker( sigS        , UT_PKA_OPERAND_SIZE, UT_PKA_MARKER_SIGN_S );
    UtPka_Fill_Marker( digest      , UT_PKA_OPERAND_SIZE, UT_PKA_MARKER_HASH );

    UtPka_Init_Poll();

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Reg_Set_RamWord32( PKA_RAM_OFF_ECDSAVRFY_RESULT, (uint32_t)PKA_STATUS_OK ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Set_EcdsaVerify( &curve, &publicKey, &signature, digest, UT_PKA_OPERAND_SIZE ) );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Reg_Get_RamWord32( UT_PKA_RM_OFF_ECDSAVRFY_MODULUS, &readBack ) );
    TEST_ASSERT_EQUAL_HEX32( UT_PKA_MARKER_MODULUS, readBack );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Reg_Get_RamWord32( UT_PKA_RM_OFF_ECDSAVRFY_A, &readBack ) );
    TEST_ASSERT_EQUAL_HEX32( UT_PKA_MARKER_A, readBack );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Reg_Get_RamWord32( UT_PKA_RM_OFF_ECDSAVRFY_GX, &readBack ) );
    TEST_ASSERT_EQUAL_HEX32( UT_PKA_MARKER_GX, readBack );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Reg_Get_RamWord32( UT_PKA_RM_OFF_ECDSAVRFY_GY, &readBack ) );
    TEST_ASSERT_EQUAL_HEX32( UT_PKA_MARKER_GY, readBack );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Reg_Get_RamWord32( UT_PKA_RM_OFF_ECDSAVRFY_ORDER_N, &readBack ) );
    TEST_ASSERT_EQUAL_HEX32( UT_PKA_MARKER_ORDER, readBack );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Reg_Get_RamWord32( UT_PKA_RM_OFF_ECDSAVRFY_QX, &readBack ) );
    TEST_ASSERT_EQUAL_HEX32( UT_PKA_MARKER_QX, readBack );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Reg_Get_RamWord32( UT_PKA_RM_OFF_ECDSAVRFY_QY, &readBack ) );
    TEST_ASSERT_EQUAL_HEX32( UT_PKA_MARKER_QY, readBack );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Reg_Get_RamWord32( UT_PKA_RM_OFF_ECDSAVRFY_SIGN_R, &readBack ) );
    TEST_ASSERT_EQUAL_HEX32( UT_PKA_MARKER_SIGN_R, readBack );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Reg_Get_RamWord32( UT_PKA_RM_OFF_ECDSAVRFY_SIGN_S, &readBack ) );
    TEST_ASSERT_EQUAL_HEX32( UT_PKA_MARKER_SIGN_S, readBack );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Reg_Get_RamWord32( UT_PKA_RM_OFF_ECDSAVRFY_HASH, &readBack ) );
    TEST_ASSERT_EQUAL_HEX32( UT_PKA_MARKER_HASH, readBack );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}

/* =============================== RAM ERASE ===================================== */

/**
 * \brief   Pka_Set_RamErase() disables and re-enables the PKA (RM0481 41.4.8: clearing EN
 *          triggers the automatic RAM erase).
 *
 * \par Expected results
 * - PKA_REQUEST_OK, PKA_CR.EN is set again at the end (the HW model re-asserts INITOK).
 */
void Ut_Pka_Set_RamErase_DisablesThenReenables( void )
{
#if defined(PKA)
    UtPka_Init_Poll();

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Set_RamErase() );
    TEST_ASSERT_EQUAL_UINT32( PKA_CR_EN, ( PKA->CR & PKA_CR_EN ) );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}

/* ============================== IRQ PRIORITY =================================== */

/**
 * \brief   Pka_Set_IrqPriority() / Pka_Get_IrqPriority() delegate to the NVIC module.
 *
 * \par Expected results
 * - Both calls forward to the mock with NVIC_PERIPH_IRQ_PKA and report its result.
 */
void Ut_Pka_IrqPriority_DelegatesToNvic( void )
{
#if defined(PKA)
    static nvic_IrqPrio_t nvicPrio = (nvic_IrqPrio_t)UT_PKA_IRQ_PRIO;
    pka_IrqPrio_t           priority = 0u;

    Nvic_Set_PeriphIrq_Prio_ExpectAndReturn( NVIC_PERIPH_IRQ_PKA, (nvic_IrqPrio_t)UT_PKA_IRQ_PRIO, NVIC_REQUEST_OK );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Set_IrqPriority( (pka_IrqPrio_t)UT_PKA_IRQ_PRIO ) );

    Nvic_Get_PeriphIrq_Prio_ExpectAndReturn( NVIC_PERIPH_IRQ_PKA, NULL, NVIC_REQUEST_OK );
    Nvic_Get_PeriphIrq_Prio_IgnoreArg_irqPrio();
    Nvic_Get_PeriphIrq_Prio_ReturnThruPtr_irqPrio( &nvicPrio );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Get_IrqPriority( &priority ) );
    TEST_ASSERT_EQUAL_UINT8( UT_PKA_IRQ_PRIO, priority );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}

/* ======================== RAM OPERAND MARSHALING (Pka_Reg) ===================== */

/**
 * \brief   Pka_Reg_Write_Operand() / Pka_Reg_Read_Operand() round-trip a size that is not
 *          a multiple of the 64-bit word (README testing section: "sizes 1 ... the maximum,
 *          the sizes that are not a multiple of the word").
 *
 * \par Expected results
 * - A 5-byte operand written with a 2-word (16-byte) area round-trips exactly, the upper
 *   11 bytes of the area are the zero guard.
 */
void Ut_Pka_RegWriteReadOperand_SizeNotWordMultiple_RoundTrips( void )
{
#if defined(PKA)
    const pka_Data_t     source[]  = { 0x11u, 0x22u, 0x33u, 0x44u, 0x55u };
    const pka_DataCnt_t   dataSize  = (pka_DataCnt_t)( sizeof( source ) / sizeof( source[0] ) );
    const pka_DataCnt_t   wordCount = UT_PKA_TWO_WORD_CNT;
    pka_Data_t             readBack[sizeof( source ) / sizeof( source[0] )] = { 0 };
    uint32_t                highWord = 0u;

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Reg_Write_Operand( PKA_RAM_OFF_MODADD_OPERAND_A, source, dataSize, wordCount ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Reg_Read_Operand( PKA_RAM_OFF_MODADD_OPERAND_A, readBack, dataSize, wordCount ) );

    TEST_ASSERT_EQUAL_MEMORY( source, readBack, dataSize );

    /* Upper 64-bit word (the zero guard word of this 2-word area) stays zero */
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK,
                       Pka_Reg_Get_RamWord32( ( PKA_RAM_OFF_MODADD_OPERAND_A + PKA_WORD_BYTES ), &highWord ) );
    TEST_ASSERT_EQUAL_UINT32( 0u, highWord );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}


/**
 * \brief   Pka_Reg_Write_Operand() rejects an operand longer than the reserved word area.
 *
 * \par Expected results
 * - PKA_REQUEST_ERROR, nothing is written (the RAM word before the area stays 0).
 */
void Ut_Pka_RegWriteOperand_TooLong_ReturnsErrorWithoutWrite( void )
{
#if defined(PKA)
    /* UT_PKA_OVERSIZE_OPERAND_BYTES (9) bytes do not fit UT_PKA_ONE_WORD_CNT (1) word (8 bytes) */
    const pka_Data_t source[UT_PKA_OVERSIZE_OPERAND_BYTES] = { 0 };
    uint32_t          regValue                              = UT_PKA_SENTINEL_REG_VALUE;

    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR,
                       Pka_Reg_Write_Operand( PKA_RAM_OFF_MODADD_OPERAND_A,
                                              source,
                                              UT_PKA_OVERSIZE_OPERAND_BYTES,
                                              UT_PKA_ONE_WORD_CNT ) );

    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Reg_Get_RamWord32( PKA_RAM_OFF_MODADD_OPERAND_A, &regValue ) );
    TEST_ASSERT_EQUAL_UINT32( 0u, regValue );
#else
    TEST_IGNORE_MESSAGE( "MCU without PKA" );
#endif
}


/**
 * \brief   Peripheral check of every function on a line without the PKA peripheral (STM32H503).
 *
 * \par Expected results
 * - Every function with a return value returns PKA_REQUEST_ERROR and writes no output.
 * - Pka_Task does nothing, the module version is returned, no mocked function is called.
 */
void Ut_Pka_NoPeripheral_EveryFunctionReturnsError( void )
{
#if !defined(PKA)
    const pka_Data_t          operand[UT_PKA_OPERAND_SIZE] = { 0 };
    pka_Data_t                result[UT_PKA_OPERAND_SIZE]  = { 0 };
    pka_Config_t              config                       = { PKA_XFER_MODE_POLL, 0u, PKA_NULL_PTR, PKA_NULL_PTR };
    pka_FunctionState_t       supported                    = PKA_FUNCTION_INACTIVE;
    pka_Bits_t                maxBits                      = 0u;
    pka_State_t               pkaState                     = PKA_STATE_UNINIT;
    pka_Result_t              opResult                     = PKA_RESULT_NONE;
    pka_IrqPrio_t             irqPriority                  = 0u;
    pka_EccPoint_t            point                        = { result, result };
    pka_EcdsaSignature_t      signature                    = { result, result };
    pka_RsaExpRequest_t       rsaRequest                   = { operand, operand, operand, result, UT_PKA_OPERAND_SIZE };
    pka_RsaCrtRequest_t       crtRequest                   = { operand, operand, operand, operand, operand, operand,
                                                               result, UT_PKA_OPERAND_SIZE };
    const pka_ModuleVersion_t version                      = Pka_Get_ModuleVersion();

    TEST_ASSERT_EQUAL_UINT8( UT_PKA_VERSION_MAJOR, version.Major );
    Pka_Task();
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Get_DefaultConfig( &config ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Init( &config ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Deinit() );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Get_Capability( PKA_OPERATION_MOD_ADD, &supported ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Get_MaxOperandBits( PKA_OPERAND_TYPE_RSA, &maxBits ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Get_State( &pkaState ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Get_Result( &opResult ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Set_ModAdd( operand, operand, operand, UT_PKA_OPERAND_SIZE, result ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Set_ModSub( operand, operand, operand, UT_PKA_OPERAND_SIZE, result ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Set_ModMul( operand, operand, operand, UT_PKA_OPERAND_SIZE, result ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR,
                       Pka_Set_ModExp( operand,
                                       operand,
                                       operand,
                                       UT_PKA_OPERAND_SIZE,
                                       PKA_FUNCTION_INACTIVE,
                                       result ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Set_ModInv( operand, operand, UT_PKA_OPERAND_SIZE, result ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR,
                       Pka_Set_ModReduce( operand, UT_PKA_OPERAND_SIZE, operand, UT_PKA_OPERAND_SIZE, result ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR,
                       Pka_Set_Arithmetic( PKA_ARITHMETIC_ADD, operand, operand, UT_PKA_OPERAND_SIZE, result ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Set_RsaExp( &rsaRequest ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Set_RsaCrtExp( &crtRequest ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Set_EccScalarMul( &PKA_CURVE_NIST_P256, operand, &point, &point ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Set_EccPointCheck( &PKA_CURVE_NIST_P256, &point, &supported ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Set_EccAdd( &PKA_CURVE_NIST_P256, &point, &point, &point ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR,
                       Pka_Set_EcdsaSign( &PKA_CURVE_NIST_P256,
                                          operand,
                                          operand,
                                          operand,
                                          UT_PKA_OPERAND_SIZE,
                                          &signature ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR,
                       Pka_Set_EcdsaVerify( &PKA_CURVE_NIST_P256, &point, &signature, operand, UT_PKA_OPERAND_SIZE ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Set_RamErase() );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Set_IrqPriority( irqPriority ) );
    TEST_ASSERT_EQUAL( PKA_REQUEST_ERROR, Pka_Get_IrqPriority( &irqPriority ) );

    TEST_ASSERT_EQUAL( PKA_FUNCTION_INACTIVE, supported );
    TEST_ASSERT_EQUAL_UINT16( 0u, maxBits );
    TEST_ASSERT_EQUAL( PKA_STATE_UNINIT, pkaState );
    TEST_ASSERT_EQUAL( PKA_RESULT_NONE, opResult );
    TEST_ASSERT_EQUAL_UINT8( 0u, result[0] );
#else
    TEST_IGNORE_MESSAGE( "MCU with PKA, see the other test cases" );
#endif /* PKA */
}

/* =========================== LOCAL FUNCTIONS ================================ */

/**
 * \brief Records every call of the configured complete callback.
 */
static void UtPka_CompleteCallback( pka_Result_t result )
{
    utPka_CallbackCnt++;
    utPka_CallbackResult = result;
}


/**
 * \brief Fills \p buffer with zero bytes except the last 4, which get the big-endian
 *        bytes of \p marker - a value distinguishable from every other operand of the
 *        same test, so a read back at the wrong RAM offset is caught instead of
 *        silently matching (the gap that let a wrong ECDSA verification offset table
 *        pass the earlier, result-only tests unnoticed).
 */
static void UtPka_Fill_Marker( pka_Data_t * const buffer, pka_DataCnt_t size, uint32_t marker )
{
    for( pka_DataCnt_t byteIdx = 0u; size > byteIdx; byteIdx++ )
    {
        buffer[byteIdx] = 0u;
    }

    if( UT_PKA_REG32_BYTES <= size )
    {
        const pka_DataCnt_t markerBase = (pka_DataCnt_t)( size - UT_PKA_REG32_BYTES );

        buffer[markerBase]       = (pka_Data_t)( ( marker >> UT_PKA_RM_BYTE3_SHIFT ) & UT_PKA_BYTE_MASK );
        buffer[markerBase + 1u]  = (pka_Data_t)( ( marker >> UT_PKA_RM_BYTE2_SHIFT ) & UT_PKA_BYTE_MASK );
        buffer[markerBase + 1u + 1u] = (pka_Data_t)( ( marker >> UT_PKA_RM_BYTE1_SHIFT ) & UT_PKA_BYTE_MASK );
        buffer[size - 1u]        = (pka_Data_t)( marker & UT_PKA_BYTE_MASK );
    }
    else
    {
        /* Buffer too small for a marker, left zeroed */
    }
}

#if defined(PKA)

/**
 * \brief HW model: PKA_SR.INITOK follows PKA_CR.EN, PKA_SR.PROCENDF follows PKA_CR.START
 *        (RegMem is plain memory, this emulates the hardware reaction the real PKA gives).
 */
static void UtPka_HwModel( void )
{
    if( PKA_CR_EN == ( PKA->CR & PKA_CR_EN ) )
    {
        PKA->SR |= PKA_SR_INITOK;
    }
    else
    {
        PKA->SR &= ~PKA_SR_INITOK;
    }

    if( PKA_CR_START == ( PKA->CR & PKA_CR_START ) )
    {
        PKA->SR |= PKA_SR_PROCENDF;
    }
    else
    {
        /* No action required */
    }
}


/**
 * \brief Sets up the CMock expectation of a successful POLL mode \ref Pka_Init.
 */
static void UtPka_Expect_InitPoll( void )
{
    Rcc_Set_PeriphActive_ExpectAndReturn( RCC_PERIPH_PKA, RCC_REQUEST_OK );
}


/**
 * \brief Initializes the module in POLL mode with the default configuration.
 */
static void UtPka_Init_Poll( void )
{
    pka_Config_t config;

    (void)Pka_Get_DefaultConfig( &config );
    UtPka_Expect_InitPoll();
    TEST_ASSERT_EQUAL( PKA_REQUEST_OK, Pka_Init( &config ) );
}

#endif /* PKA */
