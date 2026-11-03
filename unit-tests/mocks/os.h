#pragma once
/* Minimal stub of the Ledger SDK os.h for unit tests.
 * Provides only what bitcoin_app_base/src/common/script.h needs. */

#include <stdint.h>
#include <stddef.h>

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
