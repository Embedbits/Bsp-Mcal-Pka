/**
 * \defgroup Pka Pka
 * \brief Pka module
 *
 * \author Mr.Nobody
 * \file Pka_Types.h
 * \ingroup Pka
 * \brief Pka module global types definition
 *
 * This file contains the types definitions used across the module and are
 * available for other modules through the Port file. The interface is
 * identical for all families (RM0481/RM0492/RM0517, PKA chapter).
 *
 */

#ifndef PKA_PKA_TYPES_H
#define PKA_PKA_TYPES_H
/* ============================== INCLUDES ================================== */
#include "stdint.h"                         /* Standard integer types         */
/* ========================== SYMBOLIC CONSTANTS ============================ */

/** Null pointer definition */
#define PKA_NULL_PTR                        ( ( void* ) 0u )

/** Maximum RSA / DH operand size the hardware accepts (RM PKA chapter, 41.2) */
#define PKA_MAX_RSA_OPERAND_BITS            ( 4160u )

/** Maximum ECC operand size the hardware accepts (RM PKA chapter, 41.2) */
#define PKA_MAX_ECC_OPERAND_BITS            ( 640u )

/* ========================== EXPORTED MACROS =============================== */

/* ============================== TYPEDEFS ================================== */

/** \brief Type signaling major version of SW module */
typedef uint8_t pka_MajorVersion_t;

/** \brief Type signaling minor version of SW module */
typedef uint8_t pka_MinorVersion_t;

/** \brief Type signaling patch version of SW module */
typedef uint8_t pka_PatchVersion_t;

/** \brief Type signaling actual version of SW module */
typedef struct
{
    pka_MajorVersion_t Major; /**< Major version */
    pka_MinorVersion_t Minor; /**< Minor version */
    pka_PatchVersion_t Patch; /**< Patch version */
}   pka_ModuleVersion_t;

/** \brief Function status enumeration */
typedef enum
{
    PKA_FUNCTION_INACTIVE = 0u, /**< Function status is inactive */
    PKA_FUNCTION_ACTIVE         /**< Function status is active   */
}   pka_FunctionState_t;

/** \brief Enumeration used to signal request processing state */
typedef enum
{
    PKA_REQUEST_ERROR = 0u, /**< Processing request failed  */
    PKA_REQUEST_OK          /**< Processing request succeed */
}   pka_RequestState_t;

/** \brief One byte of a big-endian operand; the length is always passed next to the pointer */
typedef uint8_t pka_Data_t;

/** \brief Byte count of an operand (fits the largest supported RSA operand, 4160 bits = 520 bytes) */
typedef uint16_t pka_DataCnt_t;

/** \brief Bit count of an operand length field */
typedef uint16_t pka_Bits_t;

/** \brief Sign of a curve coefficient as written to the PKA RAM */
typedef enum
{
    PKA_SIGN_POSITIVE = 0u, /**< Coefficient is written as a positive value       */
    PKA_SIGN_NEGATIVE       /**< Coefficient is written as the opposite's modulus */
}   pka_Sign_t;

/** \brief Data transfer mode of the module */
typedef enum
{
    PKA_XFER_MODE_POLL = 0u, /**< Completion is read by \ref Pka_Task         */
    PKA_XFER_MODE_ISR,       /**< Completion is signaled by the PKA interrupt */
    PKA_XFER_MODE_UNUSED,    /**< Not a valid transfer mode                   */
    PKA_XFER_MODE_CNT        /**< Count of available transfer modes           */
}   pka_XferMode_t;

/** \brief Module operating state */
typedef enum
{
    PKA_STATE_UNINIT = 0u, /**< \ref Pka_Init was not called (or failed)    */
    PKA_STATE_IDLE,        /**< Module is initialized, no operation running */
    PKA_STATE_BUSY         /**< An operation is running in the accelerator  */
}   pka_State_t;

/** \brief Outcome of a finished PKA operation */
typedef enum
{
    PKA_RESULT_NONE = 0u,          /**< No operation finished yet                             */
    PKA_RESULT_OK,                 /**< Operation finished without error                      */
    PKA_RESULT_SIGNATURE_INVALID,  /**< ECDSA verification did not pass (not a driver error)  */
    PKA_RESULT_POINT_NOT_ON_CURVE, /**< The ECC point is not on the given curve               */
    PKA_RESULT_NO_INVERSE,         /**< The modular inversion has no result                   */
    PKA_RESULT_OPERAND_ERROR,      /**< A parameter was rejected before the hardware started  */
    PKA_RESULT_HARDWARE_ERROR      /**< RAM access error / address error reported by hardware */
}   pka_Result_t;

/** \brief Operation group used by \ref Pka_Get_Capability */
typedef enum
{
    PKA_OPERATION_MOD_ADD = 0u,    /**< Modular addition                             */
    PKA_OPERATION_MOD_SUB,         /**< Modular subtraction                          */
    PKA_OPERATION_MOD_MUL,         /**< Montgomery / modular multiplication          */
    PKA_OPERATION_MOD_EXP,         /**< Modular exponentiation (normal or protected) */
    PKA_OPERATION_MOD_INV,         /**< Modular inversion                            */
    PKA_OPERATION_MOD_REDUCE,      /**< Modular reduction                            */
    PKA_OPERATION_ARITHMETIC,      /**< Plain arithmetic add / sub / mul / compare   */
    PKA_OPERATION_RSA_EXP,         /**< RSA exponentiation                           */
    PKA_OPERATION_RSA_CRT_EXP,     /**< RSA exponentiation with the CRT parameters   */
    PKA_OPERATION_ECC_SCALAR_MUL,  /**< ECC scalar multiplication                    */
    PKA_OPERATION_ECC_POINT_CHECK, /**< Point on elliptic curve check                */
    PKA_OPERATION_ECC_ADD,         /**< ECC complete addition                        */
    PKA_OPERATION_ECDSA_SIGN,      /**< ECDSA signature generation                   */
    PKA_OPERATION_ECDSA_VERIFY,    /**< ECDSA signature verification                 */
    PKA_OPERATION_UNUSED,          /**< Not a valid operation                        */
    PKA_OPERATION_CNT              /**< Count of available operations                */
}   pka_Operation_t;

/** \brief Operand family used by \ref Pka_Get_MaxOperandBits */
typedef enum
{
    PKA_OPERAND_TYPE_RSA = 0u, /**< RSA / DH / plain arithmetic operand (ROS) */
    PKA_OPERAND_TYPE_ECC,      /**< ECC operand (EOS)                         */
    PKA_OPERAND_TYPE_UNUSED,   /**< Not a valid operand type                  */
    PKA_OPERAND_TYPE_CNT       /**< Count of available operand types          */
}   pka_OperandType_t;

/** \brief Arithmetic / plain operation selected inside \ref Pka_Set_Arithmetic */
typedef enum
{
    PKA_ARITHMETIC_ADD = 0u, /**< A + B                               */
    PKA_ARITHMETIC_SUB,      /**< A - B                               */
    PKA_ARITHMETIC_MUL,      /**< A * B                               */
    PKA_ARITHMETIC_CMP,      /**< Comparison, see \ref pka_Compare_t  */
    PKA_ARITHMETIC_UNUSED,   /**< Not a valid arithmetic operation    */
    PKA_ARITHMETIC_CNT       /**< Count of available arithmetic kinds */
}   pka_Arithmetic_t;

/** \brief Result of \ref PKA_ARITHMETIC_CMP */
typedef enum
{
    PKA_COMPARE_EQUAL = 0u, /**< Operand A is equal to operand B     */
    PKA_COMPARE_GREATER,    /**< Operand A is greater than operand B */
    PKA_COMPARE_LESS        /**< Operand A is less than operand B    */
}   pka_Compare_t;

/** \brief Interrupt priority of the PKA global interrupt (same range as \ref nvic_IrqPrio_t) */
typedef uint8_t pka_IrqPrio_t;

/** \brief Callback signature invoked by \ref Pka_Task / the PKA ISR when an operation finishes */
typedef void (*pka_CompleteCallback_t)( pka_Result_t result );

/** \brief Callback signature invoked when the hardware reports an asynchronous error */
typedef void (*pka_ErrorCallback_t)( void );

/** \brief Module configuration passed to \ref Pka_Init */
typedef struct
{
    pka_XferMode_t         XferMode;         /**< POLL (served by Pka_Task) or ISR   */
    pka_IrqPrio_t          IrqPriority;      /**< NVIC priority used in the ISR mode */
    pka_CompleteCallback_t CompleteCallback; /**< Called when an operation finishes  */
    pka_ErrorCallback_t    ErrorCallback;    /**< Called on an asynchronous HW error */
}   pka_Config_t;

/** \brief Short Weierstrass elliptic curve over GF(p): y^2 = x^3 + a*x + b (mod p) */
typedef struct
{
    const pka_Data_t *Modulus;   /**< Prime modulus p, big-endian, SizeBytes long      */
    const pka_Data_t *A;         /**< Absolute value of coefficient a                  */
    pka_Sign_t        ASign;     /**< Sign of coefficient a                            */
    const pka_Data_t *B;         /**< Coefficient b (always positive)                  */
    const pka_Data_t *Gx;        /**< Base point G, x coordinate                       */
    const pka_Data_t *Gy;        /**< Base point G, y coordinate                       */
    const pka_Data_t *Order;     /**< Order n of the base point (prime)                */
    pka_DataCnt_t     SizeBytes; /**< Byte length of Modulus / A / B / Gx / Gy / Order */
}   pka_Curve_t;

/** \brief Coordinates of a point on an elliptic curve, big-endian, curve SizeBytes long */
typedef struct
{
    pka_Data_t *X; /**< x coordinate */
    pka_Data_t *Y; /**< y coordinate */
}   pka_EccPoint_t;

/** \brief ECDSA signature, big-endian, curve SizeBytes long */
typedef struct
{
    pka_Data_t *R; /**< Signature part r */
    pka_Data_t *S; /**< Signature part s */
}   pka_EcdsaSignature_t;

/** \brief RSA modular exponentiation request (public or private operation) */
typedef struct
{
    const pka_Data_t   *Modulus;        /**< Modulus n, odd, big-endian, OperandSize long        */
    const pka_Data_t   *Exponent;       /**< Exponent e (or d), big-endian, OperandSize long     */
    const pka_Data_t   *Input;          /**< Input message / block, big-endian, OperandSize long */
    pka_Data_t         *Output;         /**< Output buffer, big-endian, OperandSize long         */
    pka_DataCnt_t       OperandSize;    /**< Byte length of Modulus / Exponent / Input / Output  */
    pka_FunctionState_t SecretExponent; /**< \ref PKA_FUNCTION_ACTIVE selects the protected mode */
}   pka_RsaExpRequest_t;

/** \brief RSA exponentiation request using the chinese remainder theorem parameters */
typedef struct
{
    const pka_Data_t *P;           /**< Prime p, big-endian, OperandSize long                    */
    const pka_Data_t *Q;           /**< Prime q, big-endian, OperandSize long                    */
    const pka_Data_t *Dp;          /**< dP = d mod (p-1), big-endian, OperandSize long           */
    const pka_Data_t *Dq;          /**< dQ = d mod (q-1), big-endian, OperandSize long           */
    const pka_Data_t *Qinv;        /**< qInv = q^-1 mod p, big-endian, OperandSize long          */
    const pka_Data_t *Input;       /**< Input message / block, big-endian, 2*OperandSize long    */
    pka_Data_t       *Output;      /**< Output buffer, big-endian, 2*OperandSize long            */
    pka_DataCnt_t     OperandSize; /**< Byte length of P / Q / Dp / Dq / Qinv (half the modulus) */
}   pka_RsaCrtRequest_t;

#endif /* PKA_PKA_TYPES_H */
