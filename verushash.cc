#include <stdint.h>
#include <mutex>
#include "crypto/verus_hash.h"

extern "C" {

static std::once_flag init_flag;

static void ensure_init()
{
    std::call_once(init_flag, []() {
        CVerusHash::init();
        CVerusHashV2::init();
    });
}

void verus_v1_hash(void *result, const void *data, size_t len)
{
    ensure_init();
    verus_hash(result, data, len);
}

void verus_v2_hash(void *result, const void *data, size_t len)
{
    ensure_init();
    CVerusHashV2 hasher(SOLUTION_VERUSHHASH_V2);
    hasher.Write((const unsigned char*)data, len);
    hasher.Finalize((unsigned char*)result);
}

void verus_v2_1_hash(void *result, const void *data, size_t len)
{
    ensure_init();
    CVerusHashV2 hasher(SOLUTION_VERUSHHASH_V2_1);
    hasher.Write((const unsigned char*)data, len);
    hasher.Finalize2b((unsigned char*)result);
}

void verus_v2_2_hash(void *result, const void *data, size_t len)
{
    ensure_init();
    CVerusHashV2 hasher(SOLUTION_VERUSHHASH_V2_2);
    hasher.Write((const unsigned char*)data, len);
    hasher.Finalize2b((unsigned char*)result);
}

}
