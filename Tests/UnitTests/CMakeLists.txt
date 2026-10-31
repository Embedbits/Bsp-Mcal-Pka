#======================== Unit tests configuration ============================#
# Unit tests of Pka module. Registered in module CMakeLists.txt by
# UnitTesting_AddPath() and created by UnitTesting_Generate() in "UnitTest"
# build (see EmBi_Platform/CMake/UnitTesting/README.md).

get_filename_component(PKA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
get_filename_component(MCAL_DIR "${PKA_DIR}/.." ABSOLUTE)

# The three sources of the module are compiled for every line: Pka.c checks the PKA
# peripheral in every function (on STM32H503, which has none, it only returns the
# error value), Pka_Reg.c and Pka_Curves.c hold the register access and the curves.
# Tests that need the real register / RAM protocol use the HW model of RegMem
# (INITOK follows EN, PROCENDF follows START) - executed serially where the model
# runs in a thread.
UnitTesting_Add_Test(
    NAME            Pka
    TEST_SOURCE     Test_Pka.c
    UUT_SOURCES     ${PKA_DIR}/Pka.c
                    ${PKA_DIR}/Pka_Reg.c
                    ${PKA_DIR}/Pka_Curves.c
    MOCK_HEADERS    ${MCAL_DIR}/Rcc/Rcc_Port.h
                    ${MCAL_DIR}/Nvic/Nvic_Port.h
    INCLUDE_DIRS    ${PKA_DIR}
                    ${MCAL_DIR}/Rcc
                    ${MCAL_DIR}/Nvic
    LINK_LIBS       ut_RegMem                           # Registers in host memory
                    ut_CmsisHost                        # CMSIS core intrinsics on host
    FORCE_INCLUDES  ${UNIT_TESTING_CMSIS_HOST_HEADER}   # Replaces cmsis_gcc.h
    HOST_LIBS       Ral_Lib                             # ST LL compiled for host
    COVERAGE_EXCLUDE ".*/Ral/.*"
    RUN_SERIAL
)
