// #include "securec.h" /* 提供 memcpy_s 等安全函数，Windows 平台上不需要此头文件 */
#include "sgl.h" /* 包含了 SGL 结构体的定义以及 SGL_HashValue 的声明。 */
#include <stdbool.h>
#include <arm_neon.h>
#include <string.h>

#define XXH64_LANE_COUNT ((size_t)4)
#define XXH64_SEED       ((uint64_t)0)
#define XXH64_STEP_SIZE  ((size_t)32)

#define XXH64_PRIME_1 ((uint64_t)0x9E3779B185EBCA87ULL)
#define XXH64_PRIME_2 ((uint64_t)0xC2B2AE3D27D4EB4FULL)
#define XXH64_PRIME_3 ((uint64_t)0x165667B19E3779F9ULL)
#define XXH64_PRIME_4 ((uint64_t)0x85EBCA77C2B2AE63ULL)
#define XXH64_PRIME_5 ((uint64_t)0x27D4EB2F165667C5ULL)

#define ROTATE_LEFT(value, shift) (value << shift) | (value >> (64 - shift))

/*
 * 用于保存 XXH64 算法的状态。
 */
typedef struct {
    uint64_t acc[XXH64_LANE_COUNT];             /* 4 个累加器。 */
    uint8_t buffer[XXH64_STEP_SIZE];            /* 保存不满 32 字节的零散数据。 */
    size_t bufferSize;                          /* 当前零散数据的大小。 */
    uint64_t totalSize;                         /* 状态已经接受的数据的总大小。 */
    bool isLarge;                               /* 状态是否已经接受了大于 32 字节的数据量。 */
} XXH64State;

static inline uint64_t XXH64_Round(uint64_t accn, uint64_t lane)
{
    // 步骤1
    accn += XXH64_PRIME_2 * lane;

    accn = (accn << 31) | (accn >> 33);

    // 步骤3
    accn *= XXH64_PRIME_1;
    return accn;
}

static inline uint64_t XXH64_MergeAccumulator(uint64_t finalAcc, uint64_t accn)
{
    uint64_t tmp = finalAcc;
    tmp = tmp ^ XXH64_Round(0, accn);
    tmp = tmp * XXH64_PRIME_1;
    tmp = tmp + XXH64_PRIME_4;
    return tmp;
}

/*
 * 如果总数据量小于 32 字节，则返回一个特殊值作为 finalAcc；否则将 4 个累加器整合为 finalAcc。
 */
static inline uint64_t XXH64_FinalAcc(XXH64State *state)
{
    register uint64_t finalAcc = ROTATE_LEFT(state->acc[0], 1);
    finalAcc += ROTATE_LEFT(state->acc[1], 7);
    finalAcc += ROTATE_LEFT(state->acc[2], 12);
    finalAcc += ROTATE_LEFT(state->acc[3], 18);

    for (size_t i = 0; i < XXH64_LANE_COUNT; i++) {
        finalAcc = XXH64_MergeAccumulator(finalAcc, state->acc[i]);
    }

    finalAcc += (uint64_t)state->totalSize;
    return finalAcc;
}

/* 对 finalAcc 进行雪崩操作、使得输入发生微小变动时，输出的每一位都有机会被翻转。 */
static inline uint64_t XXH64_Mix(uint64_t finalAcc)
{
    const int MIX_COUNT = 3;
    const int MIX_SHIFT[] = { 33, 29, 32 };
    const uint64_t MIX_MUL[] = { XXH64_PRIME_2, XXH64_PRIME_3, 1 };
    uint64_t tmp = finalAcc;
    for (size_t i = 0; i < MIX_COUNT; i++) {
        tmp ^= tmp >> MIX_SHIFT[i];
        tmp *= MIX_MUL[i];
    }
    return tmp;
}

/*
 * 将当前状态整合为哈希值返回。
 */
static inline uint64_t XXH64_Digest(XXH64State *state)
{
    uint64_t finalAcc = XXH64_FinalAcc(state);
    // finalAcc = XXH64_SolveRemaining(state, finalAcc);
    finalAcc = XXH64_Mix(finalAcc);
    return finalAcc;
}

#define Multi(input, output, step)                  \
    if (input != lastinput##step) {                 \
        output = (uint64_t)(input * XXH64_PRIME_2); \
        lastinput##step = input;                    \
        lastoutput##step = output;                  \
    } else {                                        \
        output = lastoutput##step;                  \
    }

uint64_t SGL_HashValue(SGL *sgl)
{
    XXH64State state = {};
   // XXH64_StateInit(&state);
    // memset(&state,0,sizeof(state));
    register uint64_t num1 = 0x60ea27eeadc0b5d6;
    register uint64_t num2 = 0xc2b2ae3d27d4eb4f;
    register uint64_t num3 = 0;
    register uint64_t num4 = 0x61c8864e7a143579;


    uint64_t product = 0;
    uint64_t lastinput0 = 0;
    uint64_t lastoutput0 = 0;
    uint64_t lastinput1 = 0;
    uint64_t lastoutput1 = 0;
    uint64_t lastinput2 = 0;
    uint64_t lastoutput2 = 0;
    uint64_t lastinput3 = 0;
    uint64_t lastoutput3 = 0;
    (void)(lastinput0);
    (void)(lastinput1);
    (void)(lastinput2);
    (void)(lastinput3);
    (void)(lastoutput0);
    (void)(lastoutput1);
    (void)(lastoutput2);
    (void)(lastoutput3);


    state.totalSize = sgl->entryCount * 8192;
    for (size_t i = 0; i < sgl->entryCount; i++) {
        const uint8_t *entrybuf = sgl->entries[i].buf;
        size_t entrylen = sgl->entries[i].len;
        // __builtin_prefetch(entrybuf + 520);
        for (size_t offset = 0; offset < entrylen; offset += 520) {
            // process current block
            // XXH64_Update_new(&state, entrybuf + offset, BYTE_PER_SECTOR_NOPI);
            const uint64_t *data64 = (uint64_t *)(entrybuf + offset);
            for (size_t i = 0; i < 8; ++i) {
                Multi(data64[0], product, 0);
                num1 += product;
                num1 = (uint64_t)((num1 << 31) | (num1 >> 33)) * XXH64_PRIME_1;
                // num1 += (uint64_t)(data64[0] * XXH64_PRIME_2);
                // __asm__("ROR %[accn], %[accn], %[shift]" : [accn] "+r"(num1) : [shift] "r"((unsigned int)(33)));
                // num1 *= XXH64_PRIME_1;


                Multi(data64[4], product, 1);
                num1 += product;
                num1 = (uint64_t)((num1 << 31) | (num1 >> 33)) * XXH64_PRIME_1;

                Multi(data64[1], product, 2);
                num2 += product;
                // num2 += (uint64_t)(data64[1] * XXH64_PRIME_2);
                num2 = (uint64_t)((num2 << 31) | (num2 >> 33)) * XXH64_PRIME_1;

                Multi(data64[5], product, 3);
                num2 += product;
                // num2 += (uint64_t)(data64[5] * XXH64_PRIME_2);
                num2 = (uint64_t)((num2 << 31) | (num2 >> 33)) * XXH64_PRIME_1;


                num3 += (uint64_t)(data64[2] * XXH64_PRIME_2);
                num3 = (uint64_t)((num3 << 31) | (num3 >> 33)) * XXH64_PRIME_1;

                num3 += (uint64_t)(data64[6] * XXH64_PRIME_2);
                num3 = (uint64_t)((num3 << 31) | (num3 >> 33)) * XXH64_PRIME_1;

                num4 += (uint64_t)(data64[3] * XXH64_PRIME_2);
                num4 = (uint64_t)((num4 << 31) | (num4 >> 33)) * XXH64_PRIME_1;

                num4 += (uint64_t)(data64[7] * XXH64_PRIME_2);
                num4 = (uint64_t)((num4 << 31) | (num4 >> 33)) * XXH64_PRIME_1;

                data64 += 8;
            }
        }
    }
    state.acc[0] = num1;
    state.acc[1] = num2;
    state.acc[2] = num3;
    state.acc[3] = num4;

    return XXH64_Digest(&state);
}

#include <iostream>
#include "xxhash.h"
using namespace std;
uint64_t multiply_uint64(uint64_t a, uint64_t b)
{
    uint32_t a_low = static_cast<uint32_t>(a);
    uint32_t a_high = static_cast<uint32_t>(a >> 32);

    uint32_t b_low = static_cast<uint32_t>(b);
    uint32_t b_high = static_cast<uint32_t>(b >> 32);


    // Calculate high and low parts
    uint64_t low_product = static_cast<uint64_t>(a_low) * static_cast<uint64_t>(b_low);
    uint64_t mid_product = static_cast<uint64_t>(a_low) * b_high + static_cast<uint64_t>(a_high) * b_low;

    // // Combine the high and low parts
    uint64_t result = low_product + (mid_product << 32);

    return result;
}


uint64_t multiply(uint32_t low1, uint32_t high1, uint32_t low2, uint32_t high2)
{
    uint32x2_t v1 = vdup_n_u32(low1);
    uint32x2_t v4 = vdup_n_u32(low2);

    uint32x2_t v2 = { low2, high2 };
    uint32x2_t v3 = { high1, low1 };

    uint64x2_t low_product = vmull_u32(v1, v4);
    uint64x2_t mid_product = vmull_u32(v2, v3);

    uint64x1_t low = vget_low_u64(low_product);
    cout << "multiply low: " << vget_lane_u64(low, 0) << endl;
    uint64x1_t high = vget_high_u64(mid_product);
    uint64x1_t sum = vadd_u64(low, high);

    cout << "multiply: "<< vget_lane_u64(sum, 0) << endl;

    sum = vadd_u64(vshl_n_u64(sum, 32), vget_low_u64(low_product));

    return vget_lane_u64(sum, 0);
}

uint64_t SGL_HashValue_Raw(SGL *sgl)
{
    XXH64_state_t *state = XXH64_createState();
    XXH64_reset(state, 0);
    for (size_t i = 0; i < sgl->entryCount; i++) {
        const uint8_t *entrybuf = sgl->entries[i].buf;
        size_t entrylen = sgl->entries[i].len;
        for (size_t offset = 0; offset < entrylen; offset += BYTE_PER_SECTOR_PI) {
            // prefetch the next block
            // __builtin_prefetch(entrybuf + offset + BYTE_PER_SECTOR_PI);

            // process current block
            XXH64_update(state, entrybuf + offset, BYTE_PER_SECTOR_NOPI);
        }
    }

    return XXH64_digest(state);
}

#include <chrono>
int main()
{
    SGL sgl;

    constexpr uint32_t len = 8320;
    sgl.entries[0].buf = new uint8_t[len]();
    sgl.entries[0].len = len;

    sgl.entryCount = 1;

    uint64_t expected = 0x2b5073505a48fb4;
    auto ret = SGL_HashValue_Raw(&sgl);
    if (expected != ret) {
        cout << "[raw implenment] incorrect!" << endl;
    }

    ret = SGL_HashValue(&sgl);
    if (expected != ret) {
        cout << "[my implenment] incorrect!" << endl;
    }

    cout << "[raw implenment]: ";
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < 1000; i++) {
        SGL_HashValue_Raw(&sgl);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "time cost: " << duration.count() << " us" << std::endl;

    cout << "[my implenment]:";
    start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < 1000; i++) {
        SGL_HashValue(&sgl);
    }

    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "time cost: " << duration.count() << " us" << std::endl;

    uint64_t a = UINT64_MAX - 1;
    uint64_t b = UINT64_MAX - 1000;


    register uint64_t num1 = XXH64_PRIME_1 + XXH64_PRIME_2;
    register uint64_t num2 = XXH64_PRIME_2;
    register uint64_t num3 = 0;
    register uint64_t num4 = 0 - XXH64_PRIME_1;
    cout << hex << num1 << endl;
    cout << hex << num2 << endl;
    cout << hex << num4 << endl;
}
