/**
 * \author Mr.Nobody
 * \file BspMain.h
 * \ingroup Pka
 * \brief Entry point of Pka integration test firmware (called by StartUp).
 *
 * StartUp calls BspMain() and gets this header through the interface library
 * BspMain_Lib (created by Tests/IntegrationTests/CMakeLists.txt). BspMain() is
 * implemented by ItTarget_Pka.c.
 */

#ifndef PKA_ITTEST_BSPMAIN_H
#define PKA_ITTEST_BSPMAIN_H

#ifdef __cplusplus
 extern "C" {
#endif /* __cplusplus */

/* ======================== EXPORTED FUNCTIONS ============================== */

void BspMain( void );

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PKA_ITTEST_BSPMAIN_H */
