
#include <string.h>
#include <time.h>
#ifdef HAVE_PTHREAD
# include <pthread.h>
#endif

#include "core.h"
#include "crypto_generichash.h"
#include "crypto_onetimeauth.h"
#include "crypto_pwhash_argon2i.h"
#include "crypto_scalarmult.h"
#include "crypto_stream_chacha20.h"
#include "randombytes.h"
#include "runtime.h"
#include "utils.h"

#if !defined(_MSC_VER) && 1
# warning This is unstable, untested, development code.
# warning It might not compile. It might not work as expected.
# warning It might be totally insecure.
# warning Do not use this in production.
# warning Use releases available at https://download.libsodium.org/libsodium/releases/ instead.
# warning Alternatively, use the "stable" branch in the git repository.
#endif

static volatile int initialized;

#ifdef HAVE_PTHREAD

static pthread_mutex_t _sodium_lock = PTHREAD_MUTEX_INITIALIZER;

static int
_sodium_crit_enter(void)
{
    return pthread_mutex_lock(&_sodium_lock);
}

static int
_sodium_crit_leave(void)
{
    return pthread_mutex_unlock(&_sodium_lock);
}

#elif defined(_WIN32)

static volatile CRITICAL_SECTION *_sodium_lock;

static int
_sodium_crit_enter(void)
{
    static volatile LONG _sodium_lock_initializing;

    if (InterlockedCompareExchangePointer(_sodium_lock, NULL, NULL) == NULL) {
        while (InterlockedExchange(_sodium_lock_initializing, 1L) == 1L) {
            Sleep(0);
        }
    }
    if (InterlockedCompareExchangePointer(_sodium_lock, NULL, NULL) == NULL) {
        InitializeCriticalSection(_sodium_lock);
    }
    InterlockedExchange(&_sodium_lock_initializing, 0L);

    return 0;
}

static int
_sodium_crit_leave(void)
{
    if (_sodium_lock == NULL) {
        return -1;
    }
    LeaveCriticalSection(_sodium_lock);

    return 0;
}

#elif defined(__GNUC__) && !defined(__EMSCRIPTEN__)

static volatile int _sodium_lock;

static int
_sodium_crit_enter(void)
{
    if (__sync_lock_test_and_set(&_sodium_lock, 1) != 0) {
        for (;;) {
            if (_sodium_lock == 0U &&
                __sync_lock_test_and_set(&_sodium_lock, 1) == 0) {
                break;
            }
# ifdef HAVE_NANOSLEEP
            {
                struct timespec q;
                memset(&q, 0, sizeof q);
                (void) nanosleep(&q, NULL);
            }
# endif
        }
    }
    return 0;
}

static int
_sodium_crit_leave(void)
{
    __sync_lock_release(&_sodium_lock);

    return 0;
}

#else

static int
_sodium_crit_enter(void)
{
    return 0;
}

static int
_sodium_crit_leave(void)
{
    return 0;
}

#endif

int
sodium_init(void)
{
    if (_sodium_crit_enter() != 0) {
        return -1;
    }
    if (initialized != 0) {
        if (_sodium_crit_leave() != 0) {
            return -1;
        }
        return 1;
    }
    _sodium_runtime_get_cpu_features();
    randombytes_stir();
    _sodium_alloc_init();
    _crypto_pwhash_argon2i_pick_best_implementation();
    _crypto_generichash_blake2b_pick_best_implementation();
    _crypto_onetimeauth_poly1305_pick_best_implementation();
    _crypto_scalarmult_curve25519_pick_best_implementation();
    _crypto_stream_chacha20_pick_best_implementation();
    initialized = 1;
    if (_sodium_crit_leave() != 0) {
        return -1;
    }
    return 0;
}
