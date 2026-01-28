#include <stdint.h>
#include <new>
#include "crypto/verus_hash.h"

// Einmalige Initialisierung der Hardware-Optimierungen
extern "C" void verus_hash_init_all() {
    CVerusHash::init();
    CVerusHashV2::init();
}

extern "C" {
    __attribute__((force_align_arg_pointer))
    void verus_v1_hash(void* result, const void* data, size_t len, void* obj_space) {
        CVerusHash* vh = new (obj_space) CVerusHash();
        vh->Write(reinterpret_cast<const unsigned char*>(data), len);
        vh->Finalize(reinterpret_cast<unsigned char*>(result));
        vh->~CVerusHash();
    }

    __attribute__((force_align_arg_pointer))
    void verus_v2_hash(void* result, const void* data, size_t len, void* obj_space) {
        CVerusHashV2* vh = new (obj_space) CVerusHashV2(SOLUTION_VERUSHHASH_V2);
        vh->Reset();
        vh->Write(reinterpret_cast<const unsigned char*>(data), len);
        vh->Finalize(reinterpret_cast<unsigned char*>(result));
        vh->~CVerusHashV2();
    }

    __attribute__((force_align_arg_pointer))
    void verus_v2_1_hash(void* result, const void* data, size_t len, void* obj_space) {
        CVerusHashV2* vh = new (obj_space) CVerusHashV2(SOLUTION_VERUSHHASH_V2_1);
        vh->Reset();
        vh->Write(reinterpret_cast<const unsigned char*>(data), len);
        vh->Finalize2b(reinterpret_cast<unsigned char*>(result));
        vh->~CVerusHashV2();
    }

    __attribute__((force_align_arg_pointer))
    void verus_v2_2_hash(void* result, const void* data, size_t len, void* obj_space) {
        CVerusHashV2* vh = new (obj_space) CVerusHashV2(SOLUTION_VERUSHHASH_V2_2);
        vh->Reset();
        vh->Write(reinterpret_cast<const unsigned char*>(data), len);
        vh->Finalize2b(reinterpret_cast<unsigned char*>(result));
        vh->~CVerusHashV2();
    }
}
