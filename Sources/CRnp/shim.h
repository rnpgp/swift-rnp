#ifndef SWIFT_RNP_CRNP_SHIM_H
#define SWIFT_RNP_CRNP_SHIM_H

/* Enable librnp's experimental crypto-refresh (PKESK v6 / SEIPDv2) and
 * post-quantum hybrid algorithms. These APIs are gated on
 * RNP_EXPERIMENTAL_CRYPTO_REFRESH and RNP_EXPERIMENTAL_PQC respectively
 * in rnp.h (see rnp.h:3683, 3696). The underlying librnp build at
 * v0.18.1+ already implements them; the macros only control whether the
 * C declarations are visible to consumers. We define both before
 * including the header so the Swift wrapper can call them. */
#ifndef RNP_EXPERIMENTAL_CRYPTO_REFRESH
#define RNP_EXPERIMENTAL_CRYPTO_REFRESH 1
#endif
#ifndef RNP_EXPERIMENTAL_PQC
#define RNP_EXPERIMENTAL_PQC 1
#endif

#if __has_include(<rnp/rnp.h>)
#include <rnp/rnp.h>
#else
/* Fall back to the vendored headers bundled next to this module map when
   building from Xcode without pkg-config. rnp_ver.h needs assert.h for
   static_assert, so it is included after the standard header. */
#include "rnp/rnp.h"
#include "rnp/rnp_err.h"
#include "rnp/rnp_export.h"
#include <assert.h>
#include "rnp/rnp_ver.h"
#endif

#endif /* SWIFT_RNP_CRNP_SHIM_H */
