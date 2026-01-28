#include <stdint.h>
#include "crypto/verus_hash.h"

// Einmalige Initialisierung der globalen CPU-Konstanten
static void global_setup() {
    static bool global_initialized = false;
    if (!global_initialized) {
        CVerusHash::init();
        CVerusHashV2::init();
        global_initialized = true;
    }
}

extern "C" {
    __attribute__((force_align_arg_pointer))
    void verus_v1_hash(void* result, const void* data, size_t len) {
        global_setup();
        // Objekt auf dem Stack statt auf dem Heap
        alignas(32) CVerusHash vh; 
        vh.Write(reinterpret_cast<const unsigned char*>(data), len);
        vh.Finalize(reinterpret_cast<unsigned char*>(result));
    }

    __attribute__((force_align_arg_pointer))
    void verus_v2_hash(void* result, const void* data, size_t len) {
        global_setup();
        alignas(32) CVerusHashV2 vh2(SOLUTION_VERUSHHASH_V2);
        vh2.Reset();
        vh2.Write(reinterpret_cast<const unsigned char*>(data), len);
        vh2.Finalize(reinterpret_cast<unsigned char*>(result));
    }

    __attribute__((force_align_arg_pointer))
    void verus_v2_1_hash(void* result, const void* data, size_t len) {
        global_setup();
        alignas(32) CVerusHashV2 vh2b1(SOLUTION_VERUSHHASH_V2_1);
        vh2b1.Reset();
        vh2b1.Write(reinterpret_cast<const unsigned char*>(data), len);
        vh2b1.Finalize2b(reinterpret_cast<unsigned char*>(result));
    }

    __attribute__((force_align_arg_pointer))
    void verus_v2_2_hash(void* result, const void* data, size_t len) {
        global_setup();
        alignas(32) CVerusHashV2 vh2b2(SOLUTION_VERUSHHASH_V2_2);
        vh2b2.Reset();
        vh2b2.Write(reinterpret_cast<const unsigned char*>(data), len);
        vh2b2.Finalize2b(reinterpret_cast<unsigned char*>(result));
    }
}
