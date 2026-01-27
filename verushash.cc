#include <stdint.h>
#include <mutex>
#include "crypto/verus_hash.h"

extern "C" {

bool initialized = false;

CVerusHash* vh;
CVerusHashV2* vh2;
CVerusHashV2* vh2b1;
CVerusHashV2* vh2b2;

void initialize()
{
    if (!initialized)
    {
        CVerusHash::init();
        CVerusHashV2::init();
    }
    
    vh = new CVerusHash();
    vh2 = new CVerusHashV2(SOLUTION_VERUSHHASH_V2);
    vh2b1 = new CVerusHashV2(SOLUTION_VERUSHHASH_V2_1);
	vh2b2 = new CVerusHashV2(SOLUTION_VERUSHHASH_V2_2);
    
    initialized = true;
}

void verus_v1_hash(void *result, const void *data, size_t len)
{
    initialize();
    verus_hash(result, data, len);
}

void verus_v2_hash(void *result, const void *data, size_t len)
{
    initialize();
    vh2->Reset();
    vh2->Write((const unsigned char*)data, len);
    vh2->Finalize((unsigned char *)result);
}

void verus_v2_1_hash(void *result, const void *data, size_t len)
{
    initialize();
    vh2b1->Reset();
    vh2b1->Write((const unsigned char*)data, len);
    vh2b1->Finalize2b((unsigned char*)result);
}

void verus_v2_2_hash(void *result, const void *data, size_t len)
{
    initialize();
    vh2b2->Reset();
    vh2b2->Write((const unsigned char*)data, len);
    vh2b2->Finalize2b((unsigned char*)result);
}

}