#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../target/dash_spv_masternode_processor.h"


typedef union _UInt256 {
    uint8_t u8[256 / 8];
    uint16_t u16[256 / 16];
    uint32_t u32[256 / 32];
    uint64_t u64[256 / 64];
} UInt256;

char *random_hex_256() {
    static char str[32 + 1];
    for (int i = 0; i < 32; i++) {
        sprintf(str + i, "%x", rand() % 16);
    }
    return (char *) str;
}

uint8_t* uint_malloc(void *hash, int length) {
    uint8_t *block_hash = malloc(length);
    memcpy(block_hash, hash, length);
    return block_hash;
}

struct MasternodeEntry* masternode_entry_malloc(char *id) {
    uint32_t known_confirmed_at_height = 100;
    struct MasternodeEntry *masternode_entry = malloc(sizeof(struct MasternodeEntry));
    masternode_entry->confirmed_hash = (uint8_t (*)[32]) uint_malloc(&"00000000000000000000000000000000", 32);
    masternode_entry->confirmed_hash_hashed_with_provider_registration_transaction_hash = (uint8_t (*)[32]) uint_malloc((void *) "00000000000000000000000000000000", 32);
    masternode_entry->is_valid = true;
    masternode_entry->key_id_voting = (uint8_t (*)[20]) uint_malloc(id, 20);
    masternode_entry->known_confirmed_at_height = known_confirmed_at_height;
    masternode_entry->entry_hash = (uint8_t (*)[32]) uint_malloc((void *) "00000000000000000000000000000000", 32);
    masternode_entry->operator_public_key = (uint8_t (*)[48]) uint_malloc((void *) "000000000000000000000000000000000000000000000000", 48);
    unsigned int previousOperatorPublicKeysCount = 3;
    struct OperatorPublicKey *previous_operator_public_keys = malloc(previousOperatorPublicKeysCount * sizeof(struct OperatorPublicKey));
    int i = 0;
    for (int i = 0; i < previousOperatorPublicKeysCount; i++) {
        struct OperatorPublicKey obj = {.block_height = i};
        memcpy(obj.key, (void *) "000000000000000000000000000000000000000000000000", 48);
        memcpy(obj.block_hash, (void *) "00000000000000000000000000000000", 32);
        previous_operator_public_keys[i] = obj;
    }

    masternode_entry->previous_operator_public_keys = previous_operator_public_keys;
    masternode_entry->previous_operator_public_keys_count = previousOperatorPublicKeysCount;
    unsigned int previousSimplifiedMasternodeEntryHashesCount = 3;
    struct MasternodeEntryHash *previous_masternode_entry_hashes = malloc(previousSimplifiedMasternodeEntryHashesCount * sizeof(struct MasternodeEntryHash));
    i = 0;
    for (int i = 0; i < previousSimplifiedMasternodeEntryHashesCount; i++) {
        struct MasternodeEntryHash obj = {.block_height = i};
        memcpy(obj.hash, (void *) "00000000000000000000000000000000", 32);
        memcpy(obj.block_hash, (void *) "00000000000000000000000000000000", 32);
        previous_masternode_entry_hashes[i] = obj;
    }

    masternode_entry->previous_entry_hashes = previous_masternode_entry_hashes;
    masternode_entry->previous_entry_hashes_count = previousSimplifiedMasternodeEntryHashesCount;
    unsigned int previousValidityCount = 3;
    struct Validity *previous_validity = malloc(previousValidityCount * sizeof(struct Validity));
    i = 0;
    for (int i = 0; i < previousValidityCount; i++) {
        struct Validity obj = {.block_height = i, .is_valid = true};
        memcpy(obj.block_hash, (void *)  "00000000000000000000000000000000", 32);
        previous_validity[i] = obj;
    }
    masternode_entry->previous_validity = previous_validity;
    masternode_entry->previous_validity_count = previousValidityCount;
    masternode_entry->provider_registration_transaction_hash = (uint8_t (*)[32]) uint_malloc(random_hex_256(), 32);
    masternode_entry->ip_address = (uint8_t (*)[16]) uint_malloc((void *) "0000000000000000", 16);
    masternode_entry->port = 8080;
    masternode_entry->update_height = 3;
    return masternode_entry;

}

void masternode_entry_free(struct MasternodeEntry *entry) {
     printf("masternode_entry_free: %p\n", entry);
    free(entry->confirmed_hash);
    if (entry->confirmed_hash_hashed_with_provider_registration_transaction_hash)
        free(entry->confirmed_hash_hashed_with_provider_registration_transaction_hash);
    free(entry->operator_public_key);
    free(entry->entry_hash);
    free(entry->ip_address);
    free(entry->key_id_voting);
    free(entry->provider_registration_transaction_hash);
    if (entry->previous_entry_hashes)
        free(entry->previous_entry_hashes);
    if (entry->previous_operator_public_keys)
        free(entry->previous_operator_public_keys);
    if (entry->previous_validity)
        free(entry->previous_validity);
    free(entry);
}
struct LLMQEntry * llmq_entry_malloc(char * id) {
    struct LLMQEntry *quorum_entry = malloc(sizeof(struct LLMQEntry));
    quorum_entry->all_commitment_aggregated_signature = (uint8_t (*)[96]) uint_malloc((void *) "100000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000", 96);
    quorum_entry->commitment_hash = (uint8_t (*)[32]) uint_malloc((void *) "10000000000000000000000000000000", 32);
    quorum_entry->llmq_type = LlmqtypeDevnetDIP0024;
    quorum_entry->entry_hash = (uint8_t (*)[32]) uint_malloc((void *) "10000000000000000000000000000000", 32);
    quorum_entry->llmq_hash = (uint8_t (*)[32]) uint_malloc(random_hex_256(), 32);
    quorum_entry->public_key = (uint8_t (*)[48]) uint_malloc((void *) "100000000000000000000000000000000000000000000000", 48);
    quorum_entry->threshold_signature = (uint8_t (*)[96]) uint_malloc((void *) "100000000000000000000000000000001000000000000000000000000000000010000000000000000000000000000000", 96);
    quorum_entry->verification_vector_hash = (uint8_t (*)[32]) uint_malloc((void *) "10000000000000000000000000000000", 32);
    quorum_entry->saved = true;
    quorum_entry->signers_bitset = uint_malloc((void *) "10000000000000000000000000000000", 32);
    quorum_entry->signers_bitset_length = 32;
    quorum_entry->signers_count = 32;
    quorum_entry->valid_members_bitset = uint_malloc((void *) "10000000000000000000000000000000", 32);
    quorum_entry->valid_members_bitset_length = 32;
    quorum_entry->valid_members_count = 32;
    quorum_entry->verified = true;
    quorum_entry->version = true;
    return quorum_entry;
}

void llmq_entry_free(struct LLMQEntry *entry) {
    printf("llmq_entry_free: %p\n", entry);
    free(entry->all_commitment_aggregated_signature);
    if (entry->commitment_hash)
        free(entry->commitment_hash);
    free(entry->entry_hash);
    free(entry->llmq_hash);
    free(entry->public_key);
    free(entry->threshold_signature);
    free(entry->verification_vector_hash);
    free(entry->signers_bitset);
    free(entry->valid_members_bitset);
    free(entry);
}


struct MasternodeList * masternode_list_malloc() {
    uintptr_t quorum_type_maps_count = 2;
    uintptr_t masternodes_count = 2;
    struct MasternodeList *masternode_list = malloc(sizeof(struct MasternodeList));
    struct LLMQMap **quorum_type_maps = malloc(quorum_type_maps_count * sizeof(struct LLMQMap *));
    for (int i = 0; i < quorum_type_maps_count; i++) {
        uintptr_t quorum_maps_count = 2;
        struct LLMQMap *quorums_map = malloc(sizeof(struct LLMQMap));
        struct LLMQEntry **quorums_of_type = malloc(quorum_maps_count * sizeof(struct LLMQEntry *));
        for (int j = 0; j < quorum_maps_count; j++) {
            struct LLMQEntry *entry = llmq_entry_malloc((void *) random_hex_256());
            quorums_of_type[j] = entry;
        }
        quorums_map->llmq_type = LlmqtypeDevnetDIP0024;
        quorums_map->count = quorum_maps_count;
        quorums_map->values = quorums_of_type;
        quorum_type_maps[i] = quorums_map;
    }
    struct MasternodeEntry **masternodes_values = malloc(masternodes_count * sizeof(struct MasternodeEntry *));
    for (int i = 0; i < masternodes_count; i++) {
        masternodes_values[i] = masternode_entry_malloc((void *) random_hex_256());
    }
    masternode_list->llmq_type_maps = quorum_type_maps;
    masternode_list->llmq_type_maps_count = quorum_type_maps_count;
    masternode_list->masternodes = masternodes_values;
    masternode_list->masternodes_count = masternodes_count;
    masternode_list->block_hash = (uint8_t (*)[32]) uint_malloc((void *) "10000000000000000000000000000000", 32);
    masternode_list->known_height = 3;
    masternode_list->masternode_merkle_root = (uint8_t (*)[32]) uint_malloc((void *) "00000000000000000000000000000000", 32);
    masternode_list->llmq_merkle_root = (uint8_t (*)[32]) uint_malloc((void *) "00000000000000000000000000000000", 32);
    return masternode_list;
}

void masternode_list_free(struct MasternodeList* list) {
    printf("masternode_list_free: %p\n", list);
    if (!list) return;
    free(list->block_hash);
    if (list->masternodes_count > 0) {
        for (int i = 0; i < list->masternodes_count; i++) {
            masternode_entry_free(list->masternodes[i]);
        }
    }
    if (list->masternodes)
        free(list->masternodes);
    if (list->llmq_type_maps_count > 0) {
        for (int i = 0; i < list->llmq_type_maps_count; i++) {
            struct LLMQMap *map = list->llmq_type_maps[i];
            for (int j = 0; j < map->count; j++) {
                llmq_entry_free(map->values[j]);
            }
            if (map->values)
                free(map->values);
            free(map);
        }
    }
    if (list->llmq_type_maps)
        free(list->llmq_type_maps);
    if (list->masternode_merkle_root)
        free(list->masternode_merkle_root);
    if (list->llmq_merkle_root)
        free(list->llmq_merkle_root);
    free(list);
}



uint32_t getBlockHeightByHash(uint8_t (*block_hash)[32], const void *context) {
    //DSMasternodeProcessorContext *processorContext = (__bridge DSMasternodeProcessorContext *)context;
    //uint32_t block_height = context.blockHeightLookup(block_hash);
    printf("getBlockHeightByHash: \n");
    printf("%p\n", block_hash);
    printf("%p\n", context);
    //mndiff_block_hash_destroy(block_hash);
    //return block_height;
    return 0;
}

struct MasternodeList *getMasternodeList(uint8_t (*hash)[32], const void *context) {
    struct MasternodeList* list = masternode_list_malloc();
    printf("getMasternodeList: %p\n", &list);
    return list;
}
void destroyMasternodeList(struct MasternodeList* list) {
    printf("destroyMasternodeList: %p\n", &list);
    masternode_list_free(list);
}

const struct MasternodeList *getMasternodeListConst(uint8_t (*hash)[32], const void *context) {
    const struct MasternodeList* list = masternode_list_malloc();
    printf("getMasternodeListConst: %p\n", &list);
    return list;
}
void destroyMasternodeListConst(const struct MasternodeList* list) {
    printf("destroyMasternodeListConst: %p\n", &list);
    masternode_list_free((struct MasternodeList*) list);
}

void destroyHash(uint8_t* block_hash) {
    printf("destroyHash: %p\n", block_hash);
    free(block_hash);
}


uint8_t *getMerkleRootByHash(uint8_t (*block_hash)[32], const void *context) {
    UInt256 blockHash = *((UInt256 *)block_hash);
    uint8_t (*merkle_root)[32] = malloc(32);
    memcpy(merkle_root, (const void *) "00000000000000000000000000000000", 32);
    processor_destroy_block_hash(block_hash);
    printf("getMerkleRootByHash: %p\n", &merkle_root);
    return (uint8_t *) merkle_root;
}

struct Ctx {
    const char *chain;
};


char* readQRInfo() {
    FILE *f = fopen("files/QRINFO_1_17800.dat", "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);  /* same as rewind(f); */

    char *string = malloc(fsize + 1);
    fread(string, fsize, 1, f);
    fclose(f);
    string[fsize] = 0;
    return string;
}



int main (void) {
    char *proof_hex = "01761149f5816723fdc7025790d285f63bbe26acb3471e57f28fa4db6e4859c3ae02887fcd3a7fef9b356dd12fc2e4d58c54c9e42908070dee2aaf7c7b5d389f736010017d1db154d2a87f5f5136a1b8581759b75e72d6047ee3efbfcba0889c2d4e8b6302b1a68c50747a42fd140dedcabb7c4ff3ebed1c729a1541ba1b44f1ad7c24a3e21003206c05f39cee3a2c1436b61a0746503a743658b2d0e76b432e741f9bbbe211dc34008001000000a462696458206c05f39cee3a2c1436b61a0746503a743658b2d0e76b432e741f9bbbe211dc346762616c616e63651a3b9ac7f4687265766973696f6e006a7075626c69634b65797381a36269640064646174615821032d6d975393f17c0d605efe8562c06cbfc913afcc73d0d855399c0a97d776154064747970650002163fc42a48f26886519b6e64280729c5246d92dad847823faef877eb282c7fb81001d715565e9f71ae94fe2d07568d1e2fd1043bca07c2da385dcb430cb84f92882211022325a14555b8403767a314c3bc9b8708a25e2bc756cecadf56e5184de8dcc3a31001b51e23fbb805bfd917bb0e131da4488c48417dbe82bd6d7e9d69a50abd77a3c31102f41f6cae67288cccacc79ab5c2c29fd6ec3b83919625131ec9139c65606849c61001f234e77a4845b865816729fa14801189395d2ce658c1a24130f45b076d8f047a11111102c97ff70a287f4d9741f5c54e5fc5e6a365043cdbedf623ae7d0e280a6a32b70b10018a28f5bebdbf987079878315cde74e22ef591983a576d3c6e2807ae1fd12ff8811";
    struct Ctx context = (struct Ctx){.chain = proof_hex};
    printf("------------------- test mut\n");
    test_func(getMasternodeList, destroyMasternodeList, &context);
    printf("------------------- test mut\n");
    test_func(getMasternodeList, destroyMasternodeList, &context);
    printf("------------------- test mut\n");
    test_func(getMasternodeList, destroyMasternodeList, &context);
//    test_func_const(getMasternodeListConst, destroyMasternodeListConst, &context);
}

/*
void test_qrinfo_from_message() {
    char *proof_hex = "01761149f5816723fdc7025790d285f63bbe26acb3471e57f28fa4db6e4859c3ae02887fcd3a7fef9b356dd12fc2e4d58c54c9e42908070dee2aaf7c7b5d389f736010017d1db154d2a87f5f5136a1b8581759b75e72d6047ee3efbfcba0889c2d4e8b6302b1a68c50747a42fd140dedcabb7c4ff3ebed1c729a1541ba1b44f1ad7c24a3e21003206c05f39cee3a2c1436b61a0746503a743658b2d0e76b432e741f9bbbe211dc34008001000000a462696458206c05f39cee3a2c1436b61a0746503a743658b2d0e76b432e741f9bbbe211dc346762616c616e63651a3b9ac7f4687265766973696f6e006a7075626c69634b65797381a36269640064646174615821032d6d975393f17c0d605efe8562c06cbfc913afcc73d0d855399c0a97d776154064747970650002163fc42a48f26886519b6e64280729c5246d92dad847823faef877eb282c7fb81001d715565e9f71ae94fe2d07568d1e2fd1043bca07c2da385dcb430cb84f92882211022325a14555b8403767a314c3bc9b8708a25e2bc756cecadf56e5184de8dcc3a31001b51e23fbb805bfd917bb0e131da4488c48417dbe82bd6d7e9d69a50abd77a3c31102f41f6cae67288cccacc79ab5c2c29fd6ec3b83919625131ec9139c65606849c61001f234e77a4845b865816729fa14801189395d2ce658c1a24130f45b076d8f047a11111102c97ff70a287f4d9741f5c54e5fc5e6a365043cdbedf623ae7d0e280a6a32b70b10018a28f5bebdbf987079878315cde74e22ef591983a576d3c6e2807ae1fd12ff8811";
    //&mut (FFIContext { chain }) as *mut _ as *mut std::ffi::c_void
    struct Ctx context = (struct Ctx){.chain = proof_hex};
    struct MasternodeManager *processor = register_processor(getBlockHeightByHash, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    printf("--------------\n register_processor \n--------------\n");
    printf("%p\n", processor);
//    printf("%p\n", processor->context);
    printf("\n");


    FILE *fileptr;
    char *buffer;
    long filelen;
    fileptr = fopen("files/QRINFO_1_17800.dat", "rb");  // Open the file in binary mode
    fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
    filelen = ftell(fileptr);             // Get the current byte offset in the file
    rewind(fileptr);                      // Jump back to the beginning of the file
    buffer = (char *)malloc(filelen * sizeof(char)); // Enough memory for the file
    fread(buffer, filelen, 1, fileptr); // Read in the entire file
    fclose(fileptr); // Close the file

    struct LLMQRotationInfoResult *result = process_qrinfo_from_message(buffer, filelen, 0, 0, true, 0, processor);
    printf("--------------\n process \n--------------\n");
    printf("%p\n", result);
    printf("\n");
}
*/

// clang c/main.c target/universal/release/libdash_spv_masternode_processor_macos.a -o test && ./test
