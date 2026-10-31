/**
 * \author Mr.Nobody
 * \file Pka_Reg.c
 * \ingroup Pka
 * \brief Pka module Reg component functionality.
 *
 * Register and RAM access of the module. The registers (PKA_CR, PKA_SR, PKA_CLRFR)
 * are written only here, the masks come from the CMSIS device header. The RAM
 * access converts big-endian byte operands to the little-endian 64-bit words with
 * the zero guard word that the hardware expects (RM0481/492/517, PKA chapter,
 * section 41.5.1).
 *
 * Properties of the registers, which the protocol respects (RM PKA chapter):
 * - PKA_CR.START is always read as 0, it is ignored while BUSY is set.
 * - PKA_SR.BUSY is cleared by hardware when the operation finishes (PROCENDF is set then).
 * - PKA_SR error flags (OPERRF/ADDRERRF/RAMERRF) are cleared by PKA_CLRFR, never by writing SR.
 * - PKA RAM is addressable only with 32-bit word accesses (CMSIS RAM[] array, one
 *   element per 32-bit register, two elements form one 64-bit PKA "word").
 *
 */
/* ============================== INCLUDES ================================== */
#include "Pka_Reg.h"                        /* Self include                   */
#include "Pka_Types.h"                      /* Module types definitions       */
#include "Pka.h"                            /* MODE codes, RAM offsets        */
#include "Stm32.h"                          /* PKA registers definition       */
/* ============================== TYPEDEFS ================================== */

#if defined(PKA)

/** \brief Structure type used to store physical address of PKA registers. */
typedef struct
{
    pka_RegId_t         RegId;   /**< Peripheral register ID      */
    volatile uint32_t * RegAddr; /**< Peripheral register address */
}   pka_RegList_t;

/* ======================== FORWARD DECLARATIONS ============================ */

static pka_RequestState_t Pka_Reg_Check_RamOffset( uint32_t ramOffset, pka_DataCnt_t wordCount );
static uint8_t             Pka_Reg_Get_LsbByte     ( const pka_Data_t * const data,
                                                     pka_DataCnt_t dataSize,
                                                     uint32_t bytePos );

/* ========================== SYMBOLIC CONSTANTS ============================ */

/** \brief Register value without any bit set (masked register value of an inactive bit field) */
#define PKA_REG_BITS_CLEAR              ( 0u )

/** \brief Bounded wait of \ref Pka_Reg_Set_Enable (INITOK read-back) */
#define PKA_REG_INITOK_TIMEOUT_RAW       ( 0x100000u )

/** \brief Mask of every PKA_SR error flag cleared after an operation */
#define PKA_REG_SR_ERROR_MASK           ( PKA_SR_OPERRF | PKA_SR_ADDRERRF | PKA_SR_RAMERRF )

/** \brief Mask of every PKA_CLRFR clear bit used after an operation */
#define PKA_REG_CLRFR_ALL_MASK          ( PKA_CLRFR_PROCENDFC | PKA_CLRFR_OPERRFC | \
                                          PKA_CLRFR_ADDRERRFC | PKA_CLRFR_RAMERRFC )

/** \brief Mask of every PKA_CR interrupt enable bit */
#define PKA_REG_CR_IRQ_MASK             ( PKA_CR_PROCENDIE | PKA_CR_OPERRIE | PKA_CR_ADDRERRIE | PKA_CR_RAMERRIE )

/** \brief Byte width of the AHB 32-bit single accesses the PKA RAM is read/written with */
#define PKA_REG_BYTES_PER_WORD32        ( 4u )

/** \brief Mask of the least significant byte of a 32-bit value */
#define PKA_REG_BYTE_MASK               ( 0xFFu )

/** \brief Bit shift of the second byte (index 1) of a little-endian 32-bit value */
#define PKA_REG_BYTE1_SHIFT_BITS        ( 8u )

/** \brief Bit shift of the third byte (index 2) of a little-endian 32-bit value */
#define PKA_REG_BYTE2_SHIFT_BITS        ( 16u )

/** \brief Bit shift of the fourth byte (index 3) of a little-endian 32-bit value */
#define PKA_REG_BYTE3_SHIFT_BITS        ( 24u )

/** \brief Word count of a single 32-bit RAM access (\ref Pka_Reg_Check_RamOffset) */
#define PKA_REG_SINGLE_WORD_CNT         ( 1u )

/* =============================== MACROS =================================== */

/* ========================== EXPORTED VARIABLES ============================ */

/* =========================== LOCAL VARIABLES ============================== */

/** \brief PKA registers configuration structure (reduces code size while referring to the registers) */
static const pka_RegList_t             pka_RegList[] =
{
    { .RegId = PKA_REG_CR    , .RegAddr = &(PKA->CR   ) }, /**< PKA control register     */
    { .RegId = PKA_REG_SR    , .RegAddr = &(PKA->SR   ) }, /**< PKA status register      */
    { .RegId = PKA_REG_CLRFR , .RegAddr = &(PKA->CLRFR) }, /**< PKA clear flag register  */
};

_Static_assert( (sizeof(pka_RegList) / sizeof(pka_RegList_t)) == PKA_REG_CNT,
                "Pka_Reg: pka_RegList has incorrect size." );

/* ========================= EXPORTED FUNCTIONS ============================= */

/**
 * \brief Sets the register bit with given mask.
 *
 * \param regId   [in]: PKA register ID
 * \param bitMask [in]: Mask to apply to the register
 */
void Pka_Set_RegBit( pka_RegId_t regId, uint32_t bitMask )
{
    if( PKA_REG_CNT > regId )
    {
        *pka_RegList[regId].RegAddr |= bitMask;
    }
    else
    {
        /* Invalid register ID, no action required */
    }
}


/**
 * \brief Resets the register bit with given mask.
 *
 * \param regId   [in]: PKA register ID
 * \param bitMask [in]: Mask to apply to the register
 */
void Pka_Reset_RegBit( pka_RegId_t regId, uint32_t bitMask )
{
    if( PKA_REG_CNT > regId )
    {
        *pka_RegList[regId].RegAddr &= ~bitMask;
    }
    else
    {
        /* Invalid register ID, no action required */
    }
}


/**
 * \brief Gets the register bit value with given mask.
 *
 * \param regId   [in]: PKA register ID
 * \param bitMask [in]: Mask to apply to the register
 * \return Register bit value with applied mask, no bit set for invalid register ID
 */
uint32_t Pka_Get_RegBit( pka_RegId_t regId, uint32_t bitMask )
{
    uint32_t retValue = PKA_REG_BITS_CLEAR;

    if( PKA_REG_CNT > regId )
    {
        retValue = ( *pka_RegList[regId].RegAddr & bitMask );
    }
    else
    {
        /* Invalid register ID, no bit is set */
        retValue = PKA_REG_BITS_CLEAR;
    }

    return ( retValue );
}


/**
 * \brief Updates the register value with given mask and value.
 *
 * \param regId    [in]: PKA register ID
 * \param regMask  [in]: Mask to apply to the register
 * \param regValue [in]: Value to set in the register
 */
void Pka_Set_RegVal( pka_RegId_t regId, uint32_t regMask, uint32_t regValue )
{
    if( PKA_REG_CNT > regId )
    {
        *pka_RegList[regId].RegAddr = ( ( *pka_RegList[regId].RegAddr & ~regMask ) |
                                        ( regValue & regMask ) );
    }
    else
    {
        /* Invalid register ID, no action required */
    }
}


/**
 * \brief Gets the register value with given mask.
 *
 * \param regId   [in]: PKA register ID
 * \param regMask [in]: Mask to apply to the register
 * \return Register value with applied mask, no bit set for invalid register ID
 */
uint32_t Pka_Get_RegVal( pka_RegId_t regId, uint32_t regMask )
{
    uint32_t retValue = PKA_REG_BITS_CLEAR;

    if( PKA_REG_CNT > regId )
    {
        retValue = ( *pka_RegList[regId].RegAddr & regMask );
    }
    else
    {
        /* Invalid register ID, no bit is set */
        retValue = PKA_REG_BITS_CLEAR;
    }

    return ( retValue );
}


/**
 * \brief Writes one 32-bit word of the PKA RAM.
 *
 * \param ramOffset [in]: Offset from the PKA base address, as given by the reference manual
 * \param value     [in]: Value to write
 *
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR for an offset outside the RAM
 *         or not aligned on a 32-bit boundary (nothing is written).
 */
pka_RequestState_t Pka_Reg_Set_RamWord32( uint32_t ramOffset, uint32_t value )
{
    pka_RequestState_t retState   = PKA_REQUEST_ERROR;
    const pka_RequestState_t offsetState = Pka_Reg_Check_RamOffset( ramOffset, PKA_REG_SINGLE_WORD_CNT );

    if( PKA_REQUEST_OK == offsetState )
    {
        const uint32_t wordIndex = ( ( ramOffset - PKA_RAM_BASE_OFFSET ) / PKA_REG_BYTES_PER_WORD32 );

        PKA->RAM[wordIndex] = value;
        retState            = PKA_REQUEST_OK;
    }
    else
    {
        /* Offset out of range, nothing is written */
        retState = PKA_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Reads one 32-bit word of the PKA RAM.
 *
 * \param ramOffset [in]:  Offset from the PKA base address, as given by the reference manual
 * \param value     [out]: Pointer to the read value (not changed on error)
 *
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR for an offset outside the RAM,
 *         not aligned on a 32-bit boundary, or a \ref PKA_NULL_PTR value.
 */
pka_RequestState_t Pka_Reg_Get_RamWord32( uint32_t ramOffset, uint32_t * const value )
{
    pka_RequestState_t retState   = PKA_REQUEST_ERROR;
    const pka_RequestState_t offsetState = Pka_Reg_Check_RamOffset( ramOffset, PKA_REG_SINGLE_WORD_CNT );

    if( ( PKA_NULL_PTR    != value ) &&
        ( PKA_REQUEST_OK  == offsetState )    )
    {
        const uint32_t wordIndex = ( ( ramOffset - PKA_RAM_BASE_OFFSET ) / PKA_REG_BYTES_PER_WORD32 );

        *value    = PKA->RAM[wordIndex];
        retState  = PKA_REQUEST_OK;
    }
    else
    {
        /* Offset out of range or no output pointer, nothing is read */
        retState = PKA_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Writes a length field (one 64-bit RAM word, no guard word) in bits.
 *
 * \param ramOffset [in]: Offset of the length field
 * \param bits      [in]: Length in bits
 *
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR for an offset outside the RAM.
 */
pka_RequestState_t Pka_Reg_Write_Length( uint32_t ramOffset, pka_Bits_t bits )
{
    pka_RequestState_t retState   = PKA_REQUEST_ERROR;
    const pka_RequestState_t offsetState = Pka_Reg_Check_RamOffset( ramOffset, PKA_REG_SINGLE_WORD_CNT );

    if( PKA_REQUEST_OK == offsetState )
    {
        (void)Pka_Reg_Set_RamWord32( ramOffset               , (uint32_t)bits );
        (void)Pka_Reg_Set_RamWord32( ( ramOffset + PKA_REG_BYTES_PER_WORD32 ), PKA_REG_BITS_CLEAR );
        retState = PKA_REQUEST_OK;
    }
    else
    {
        /* Offset out of range, nothing is written */
        retState = PKA_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Writes a big-endian byte operand as the little-endian 64-bit RAM words
 *        the hardware expects, zero-padded up to \p wordCount words.
 *
 * \param ramOffset [in]: Offset of the least significant word of the operand
 * \param data      [in]: Big-endian byte array (the most significant byte first)
 * \param dataSize  [in]: Length of \p data in bytes
 * \param wordCount [in]: Number of 64-bit words reserved for the operand (ROS / EOS,
 *                        already includes the zero guard word)
 *
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR when the area does not fit
 *         the RAM, \p data does not fit \p wordCount, or \p data is \ref PKA_NULL_PTR.
 */
pka_RequestState_t Pka_Reg_Write_Operand( uint32_t ramOffset,
                                          const pka_Data_t * const data,
                                          pka_DataCnt_t dataSize,
                                          pka_DataCnt_t wordCount )
{
    pka_RequestState_t retState    = PKA_REQUEST_ERROR;
    const uint32_t      totalBytes  = ( (uint32_t)wordCount * PKA_WORD_BYTES );
    const pka_RequestState_t offsetState = Pka_Reg_Check_RamOffset( ramOffset, wordCount );

    if( ( PKA_NULL_PTR   != data ) &&
        ( totalBytes     >= dataSize ) &&
        ( PKA_REQUEST_OK == offsetState )    )
    {
        for( uint32_t regByteOffset = 0u; totalBytes > regByteOffset; regByteOffset += PKA_REG_BYTES_PER_WORD32 )
        {
            const uint8_t byte0  = Pka_Reg_Get_LsbByte( data, dataSize, regByteOffset       );
            const uint8_t byte1  = Pka_Reg_Get_LsbByte( data, dataSize, ( regByteOffset + 1u ) );
            const uint8_t byte2  = Pka_Reg_Get_LsbByte( data, dataSize, ( regByteOffset + 2u ) );
            const uint8_t byte3  = Pka_Reg_Get_LsbByte( data, dataSize, ( regByteOffset + 3u ) );
            const uint32_t regValue = ( (uint32_t)byte0 |
                                        ( (uint32_t)byte1 << PKA_REG_BYTE1_SHIFT_BITS ) |
                                        ( (uint32_t)byte2 << PKA_REG_BYTE2_SHIFT_BITS ) |
                                        ( (uint32_t)byte3 << PKA_REG_BYTE3_SHIFT_BITS ) );

            (void)Pka_Reg_Set_RamWord32( ( ramOffset + regByteOffset ), regValue );
        }

        retState = PKA_REQUEST_OK;
    }
    else
    {
        /* Invalid operand or area does not fit, nothing is written */
        retState = PKA_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Reads \p wordCount little-endian 64-bit RAM words back as a big-endian byte operand.
 *
 * \param ramOffset [in]:  Offset of the least significant word of the operand
 * \param data      [out]: Big-endian byte array to fill (the most significant byte first)
 * \param dataSize  [in]:  Length of \p data in bytes
 * \param wordCount [in]:  Number of 64-bit words of the result area
 *
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR when the area does not fit
 *         the RAM, \p data does not fit \p wordCount, or \p data is \ref PKA_NULL_PTR.
 */
pka_RequestState_t Pka_Reg_Read_Operand( uint32_t ramOffset,
                                         pka_Data_t * const data,
                                         pka_DataCnt_t dataSize,
                                         pka_DataCnt_t wordCount )
{
    pka_RequestState_t retState    = PKA_REQUEST_ERROR;
    const uint32_t      totalBytes  = ( (uint32_t)wordCount * PKA_WORD_BYTES );
    const pka_RequestState_t offsetState = Pka_Reg_Check_RamOffset( ramOffset, wordCount );

    if( ( PKA_NULL_PTR   != data ) &&
        ( totalBytes     >= dataSize ) &&
        ( PKA_REQUEST_OK == offsetState )    )
    {
        for( uint32_t bytePos = 0u; dataSize > bytePos; bytePos++ )
        {
            uint32_t             regValue    = PKA_REG_BITS_CLEAR;
            const uint32_t       regByteOffset = ( bytePos & ~0x03u );
            const pka_RequestState_t readState  = Pka_Reg_Get_RamWord32( ( ramOffset + regByteOffset ), &regValue );

            if( PKA_REQUEST_OK == readState )
            {
                const uint32_t byteShift = ( ( bytePos & 0x03u ) * 8u );

                data[( dataSize - 1u ) - bytePos] = (uint8_t)( ( regValue >> byteShift ) & PKA_REG_BYTE_MASK );
            }
            else
            {
                /* Should not happen, bounds were already checked */
                data[( dataSize - 1u ) - bytePos] = 0u;
            }
        }

        retState = PKA_REQUEST_OK;
    }
    else
    {
        /* Invalid buffer or area does not fit, nothing is read */
        retState = PKA_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Reads a 64-bit hardware status / error word (only the low 32 bits carry the code).
 *
 * \param ramOffset [in]:  Offset of the status word
 * \param status    [out]: Pointer to the read status code (not changed on error)
 *
 * \return \ref PKA_REQUEST_OK, or \ref PKA_REQUEST_ERROR for an offset outside the RAM
 *         or a \ref PKA_NULL_PTR value.
 */
pka_RequestState_t Pka_Reg_Read_Status( uint32_t ramOffset, uint32_t * const status )
{
    return ( Pka_Reg_Get_RamWord32( ramOffset, status ) );
}


/**
 * \brief Enables the PKA and waits until the initialization completes (INITOK).
 *
 * EN is written together with the MODE of the ECDSA verification: the mode written with EN has to be an
 * authorized operation, otherwise OPERRF is set and the following MODE writes are ignored; on the lines with the PKA
 * in the limited mode (PKA_SR.LMF = 1) the ECDSA verification is the only authorized one (RM0481 41.4.5, PKA_CR.MODE).
 * The write is repeated while EN stays clear (the setting of EN is ignored while the PKA RAM is being cleared,
 * RM0481 41.4.3), and the error flags raised by the enabling are cleared at the end.
 *
 * \return \ref PKA_REQUEST_OK if INITOK was read back within the timeout.
 *         \ref PKA_REQUEST_ERROR otherwise.
 */
pka_RequestState_t Pka_Reg_Set_Enable( void )
{
    pka_RequestState_t retState = PKA_REQUEST_ERROR;
    const uint32_t       enableValue = ( ( (uint32_t)PKA_MODE_ECDSA_VERIFY << PKA_CR_MODE_Pos ) | PKA_CR_EN );

    for( uint32_t iterationCnt = 0u; PKA_REG_INITOK_TIMEOUT_RAW > iterationCnt; iterationCnt++ )
    {
        const uint32_t            enableBit   = Pka_Get_RegBit( PKA_REG_CR, PKA_CR_EN );
        const pka_FunctionState_t initOkState = Pka_Reg_Get_InitOk();

        if( PKA_REG_BITS_CLEAR == enableBit )
        {
            /* EN is clear (first pass, or the write was ignored): write it again */
            Pka_Set_RegVal( PKA_REG_CR, ( PKA_CR_MODE | PKA_CR_EN ), enableValue );
            retState = PKA_REQUEST_ERROR;
        }
        else if( PKA_FUNCTION_ACTIVE == initOkState )
        {
            retState = PKA_REQUEST_OK;
            break;
        }
        else
        {
            /* Initialization is not confirmed yet */
            retState = PKA_REQUEST_ERROR;
        }
    }

    Pka_Set_RegVal( PKA_REG_CLRFR, PKA_REG_CLRFR_ALL_MASK, PKA_REG_CLRFR_ALL_MASK );

    return ( retState );
}


/**
 * \brief Disables the PKA (also triggers the automatic RAM erase, RM 41.4.8).
 */
void Pka_Reg_Set_Disable( void )
{
    Pka_Reset_RegBit( PKA_REG_CR, PKA_CR_EN );
}


/**
 * \brief Returns the PKA initialization flag.
 *
 * \return \ref PKA_FUNCTION_ACTIVE if PKA_SR.INITOK is set, otherwise \ref PKA_FUNCTION_INACTIVE.
 */
pka_FunctionState_t Pka_Reg_Get_InitOk( void )
{
    pka_FunctionState_t retState = PKA_FUNCTION_INACTIVE;
    const uint32_t       bitValue = Pka_Get_RegBit( PKA_REG_SR, PKA_SR_INITOK );

    if( PKA_REG_BITS_CLEAR != bitValue )
    {
        retState = PKA_FUNCTION_ACTIVE;
    }
    else
    {
        retState = PKA_FUNCTION_INACTIVE;
    }

    return ( retState );
}


/**
 * \brief Selects the operation, starts it and waits (bounded) for its completion.
 *
 * The operands must already be written to the PKA RAM. The error flags are
 * cleared together with PROCENDF before returning, so a following call starts
 * from a clean status register.
 *
 * \param modeCode [in]: MODE[5:0] value of the requested operation
 *
 * \return \ref PKA_REG_RUN_OK on PROCENDF, \ref PKA_REG_RUN_HW_ERROR on an error
 *         flag, \ref PKA_REG_RUN_TIMEOUT if neither was set within the bounded wait.
 */
pka_RegRunResult_t Pka_Reg_Run( pka_ModeCode_t modeCode )
{
    pka_RegRunResult_t retResult = PKA_REG_RUN_TIMEOUT;
    const uint32_t       modeValue = ( (uint32_t)modeCode << PKA_CR_MODE_Pos );

    Pka_Set_RegVal( PKA_REG_CR, ( PKA_CR_MODE | PKA_CR_START ), ( modeValue | PKA_CR_START ) );

    for( uint32_t iterationCnt = 0u; PKA_REG_TIMEOUT_RAW > iterationCnt; iterationCnt++ )
    {
        const uint32_t statusReg = Pka_Get_RegVal( PKA_REG_SR, ( PKA_SR_PROCENDF | PKA_REG_SR_ERROR_MASK ) );

        if( PKA_REG_BITS_CLEAR != ( statusReg & PKA_REG_SR_ERROR_MASK ) )
        {
            retResult = PKA_REG_RUN_HW_ERROR;
            break;
        }
        else if( PKA_SR_PROCENDF == ( statusReg & PKA_SR_PROCENDF ) )
        {
            retResult = PKA_REG_RUN_OK;
            break;
        }
        else
        {
            /* Operation still in progress */
        }
    }

    Pka_Set_RegVal( PKA_REG_CLRFR, PKA_REG_CLRFR_ALL_MASK, PKA_REG_CLRFR_ALL_MASK );

    return ( retResult );
}


/**
 * \brief Returns the PKA busy flag.
 *
 * \return \ref PKA_FUNCTION_ACTIVE while an operation is running, otherwise \ref PKA_FUNCTION_INACTIVE.
 */
pka_FunctionState_t Pka_Reg_Get_BusyState( void )
{
    pka_FunctionState_t retState = PKA_FUNCTION_INACTIVE;
    const uint32_t       bitValue = Pka_Get_RegBit( PKA_REG_SR, PKA_SR_BUSY );

    if( PKA_REG_BITS_CLEAR != bitValue )
    {
        retState = PKA_FUNCTION_ACTIVE;
    }
    else
    {
        retState = PKA_FUNCTION_INACTIVE;
    }

    return ( retState );
}


/**
 * \brief Enables or disables every PKA interrupt source used by the ISR transfer mode.
 *
 * \param enableState [in]: \ref PKA_FUNCTION_ACTIVE enables PROCENDIE/OPERRIE/ADDRERRIE/RAMERRIE
 */
void Pka_Reg_Set_IrqEnable( pka_FunctionState_t enableState )
{
    if( PKA_FUNCTION_ACTIVE == enableState )
    {
        Pka_Set_RegBit( PKA_REG_CR, PKA_REG_CR_IRQ_MASK );
    }
    else
    {
        Pka_Reset_RegBit( PKA_REG_CR, PKA_REG_CR_IRQ_MASK );
    }
}

/* =========================== LOCAL FUNCTIONS ============================== */

/**
 * \brief Checks that an operand area of \p wordCount 64-bit words starting at
 *        \p ramOffset is fully inside the PKA RAM and word aligned.
 *
 * \param ramOffset [in]: Offset from the PKA base address
 * \param wordCount [in]: Number of 64-bit words of the area (minimum 1)
 *
 * \return \ref PKA_REQUEST_OK if the area is valid, otherwise \ref PKA_REQUEST_ERROR.
 */
static pka_RequestState_t Pka_Reg_Check_RamOffset( uint32_t ramOffset, pka_DataCnt_t wordCount )
{
    pka_RequestState_t retState   = PKA_REQUEST_ERROR;
    const uint32_t       areaBytes  = ( (uint32_t)wordCount * PKA_WORD_BYTES );
    const uint32_t       alignMask  = 0x03u;

    if( ( PKA_REG_BITS_CLEAR          == ( ramOffset & alignMask )          ) &&
        ( PKA_RAM_BASE_OFFSET          <= ramOffset                         ) &&
        ( 0u                          < wordCount                          ) &&
        ( ( PKA_RAM_BASE_OFFSET + PKA_RAM_SIZE_BYTES ) >= ( ramOffset + areaBytes ) )    )
    {
        retState = PKA_REQUEST_OK;
    }
    else
    {
        /* Offset or size outside the RAM, or not 32-bit aligned */
        retState = PKA_REQUEST_ERROR;
    }

    return ( retState );
}


/**
 * \brief Returns the byte of \p data at the little-endian bit position \p bytePos,
 *        counting from the least significant byte, zero beyond \p dataSize.
 *
 * \param data     [in]: Big-endian byte array (the most significant byte first)
 * \param dataSize [in]: Length of \p data in bytes
 * \param bytePos  [in]: Requested position, 0 is the least significant byte
 *
 * \return The requested byte, or 0 for \p bytePos beyond \p dataSize (guard bytes).
 */
static uint8_t Pka_Reg_Get_LsbByte( const pka_Data_t * const data, pka_DataCnt_t dataSize, uint32_t bytePos )
{
    uint8_t retByte = 0u;

    if( (uint32_t)dataSize > bytePos )
    {
        retByte = data[( dataSize - 1u ) - bytePos];
    }
    else
    {
        /* Position beyond the operand, guard byte stays 0 */
        retByte = 0u;
    }

    return ( retByte );
}

#endif /* PKA */
