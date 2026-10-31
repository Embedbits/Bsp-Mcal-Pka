#===================== Integration tests configuration ========================#
# Integration tests of Pka module on target. Registered in module CMakeLists.txt
# by IntegrationTesting_AddPath() and created by IntegrationTesting_Generate() in
# "IntegrationTest" build (see EmBi_Platform/CMake/IntegrationTesting/README.md).
#
# The test set is independent - target interface (entry point, initialization,
# fault handlers, system reset) is implemented by ItTarget_Pka.c and
# all libraries of the firmware are listed here.
#
# The firmware is flashed and run on the board of the IT agent.

# StartUp calls BspMain() - the entry point of the test firmware is provided by
# the test set (BspMain.h, ItTarget_Pka.c)
if(NOT TARGET BspMain_Lib)
    add_library(BspMain_Lib INTERFACE)
    target_include_directories(BspMain_Lib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
endif()

IntegrationTesting_Add_Test(
    NAME            Pka
    TEST_SOURCE     ItTest_Pka.c
    SOURCES         ItTarget_Pka.c      # Target interface of the test set
    LINK_LIBS       StartUp_Lib         # Startup code (calls BspMain)
                    Nvic_Lib            # Fault handlers, system reset (ItTarget)
                    Pka_Lib
                    Rng_Lib             # RNG feeds the PKA (INITOK)
    TIMEOUT         60
)
