#ifndef SHA256_STORE_H
#define SHA256_STORE_H

#include "dht/dhtstore/DHTStoreModule.h"
#include "memory/MemAllocator.h"

void SHA256Store_register(struct DHTStoreRegistry* registry, const struct MemAllocator* storeAllocator);

#endif
