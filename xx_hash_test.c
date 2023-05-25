// #include "securec.h" /* 提供 memcpy_s 等安全函数，Windows 平台上不需要此头文件 */
#include "sgl.h" /* 包含了 SGL 结构体的定义以及 SGL_HashValue 的声明。 */
#include <stdbool.h>
#include <arm_neon.h>

#define XXH64_LANE_COUNT ((size_t)4)
#define XXH64_SEED       ((uint64_t)0)
#define XXH64_STEP_SIZE  ((size_t)32)

#define XXH64_PRIME_1 ((uint64_t)0x9E3779B185EBCA87ULL)
#define XXH64_PRIME_2 ((uint64_t)0xC2B2AE3D27D4EB4FULL)
#define XXH64_PRIME_3 ((uint64_t)0x165667B19E3779F9ULL)
#define XXH64_PRIME_4 ((uint64_t)0x85EBCA77C2B2AE63ULL)
#define XXH64_PRIME_5 ((uint64_t)0x27D4EB2F165667C5ULL)

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

static uint64_t inline XXH64_Read64(const uint8_t *data)
{
    return *(const uint64_t *)data;
}

/*
 * 初始化 XXH64 算法的状态。
 */
static void XXH64_StateInit(XXH64State *state)
{
    static const uint64_t INIT_ACC[] = {
        XXH64_SEED + XXH64_PRIME_1 + XXH64_PRIME_2,
        XXH64_SEED + XXH64_PRIME_2,
        XXH64_SEED,
        XXH64_SEED - XXH64_PRIME_1,
    };

    state->bufferSize = 0;
    state->totalSize = 0;
    state->isLarge = false;
    for (size_t i = 0; i < XXH64_LANE_COUNT; i++) {
        state->acc[i] = INIT_ACC[i];
    }
}

/*
 * 返回 x 循环左移 n 位的结果。
 */
static inline uint64_t XXH64_RotateLeft(uint64_t value, uint8_t shift)
{
    __asm__("ROR %[value], %[value], %[shift]"
            : [value] "+r"(value)
            : [shift] "r"((unsigned int)(33)));
    return value;
}

static inline uint64_t XXH64_Round(uint64_t accn, uint64_t lane)
{
    // 步骤1
    accn += XXH64_PRIME_2 * lane;

    // 步骤2: 循环左移31位
    // uint64x2_t v = vld1q_u64(&accn);
    // uint64x2_t result = vorrq_u64(vshlq_n_u64(v, 31), vshrq_n_u64(v, 33));
    // vst1q_lane_u64(&accn, result, 0);

    // accn = (accn << 31) | (accn >> 33);
    __asm__("ROR %[accn], %[accn], %[shift]" : [accn] "+r"(accn) : [shift] "r"((unsigned int)(33)));

    // 步骤3
    accn *= XXH64_PRIME_1;
    return accn;
}

static uint64_t XXH64_MergeAccumulator(uint64_t finalAcc, uint64_t accn)
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
static uint64_t XXH64_FinalAcc(XXH64State *state)
{
    static const int ROTATE_LEFT[] = { 1, 7, 12, 18 };

    uint64_t finalAcc = 0;

    for (size_t i = 0; i < XXH64_LANE_COUNT; i++) {
        finalAcc += XXH64_RotateLeft(state->acc[i], ROTATE_LEFT[i]);
    }
    for (size_t i = 0; i < XXH64_LANE_COUNT; i++) {
        finalAcc = XXH64_MergeAccumulator(finalAcc, state->acc[i]);
    }

    finalAcc += (uint64_t)state->totalSize;
    return finalAcc;
}

/* 对 finalAcc 进行雪崩操作、使得输入发生微小变动时，输出的每一位都有机会被翻转。 */
static uint64_t XXH64_Mix(uint64_t finalAcc)
{
    static const int MIX_COUNT = 3;
    static const int MIX_SHIFT[] = { 33, 29, 32 };
    static const uint64_t MIX_MUL[] = { XXH64_PRIME_2, XXH64_PRIME_3, 1 };
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
static uint64_t XXH64_Digest(XXH64State *state)
{
    uint64_t finalAcc = XXH64_FinalAcc(state);
    finalAcc = XXH64_Mix(finalAcc);
    return finalAcc;
}

uint64_t SGL_HashValue(SGL *sgl)
{
    XXH64State state = {};
    XXH64_StateInit(&state);
    register uint64_t num1 = state.acc[0];
    register uint64_t num2 = state.acc[1];
    register uint64_t num3 = state.acc[2];
    register uint64_t num4 = state.acc[3];

    const uint64_t shift = 31;
    const uint64_t shiftRight = 31;

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

                num1 += (uint64_t)(data64[0] * XXH64_PRIME_2);
                __asm__("ROR %[num1], %[num1], %[shift]" : [num1] "+r"(num1) : [shift] "r"(shiftRight)); 
                num1 *= XXH64_PRIME_1;

                num2 += (uint64_t)(data64[1] * XXH64_PRIME_2);
                __asm__("ROR %[num2], %[num2], %[shift]" : [num2] "+r"(num2) : [shift] "r"(shiftRight)); 
                num2 *= XXH64_PRIME_1;

                num3 += (uint64_t)(data64[2] * XXH64_PRIME_2);
                __asm__("ROR %[num3], %[num3], %[shift]" : [num3] "+r"(num3) : [shift] "r"(shiftRight)); 
                num3 *= XXH64_PRIME_1;

                num4 += (uint64_t)(data64[3] * XXH64_PRIME_2);
                __asm__("ROR %[num4], %[num4], %[shift]" : [num4] "+r"(num4) : [shift] "r"(shiftRight)); 
                num4 *= XXH64_PRIME_1;

                num1 += (uint64_t)(data64[4] * XXH64_PRIME_2);
                __asm__("ROR %[num1], %[num1], %[shift]" : [num1] "+r"(num1) : [shift] "r"(shiftRight)); 
                num1 *= XXH64_PRIME_1;

                num2 += (uint64_t)(data64[5] * XXH64_PRIME_2);
                __asm__("ROR %[num2], %[num2], %[shift]" : [num2] "+r"(num2) : [shift] "r"(shiftRight)); 
                num2 *= XXH64_PRIME_1;

                num3 += (uint64_t)(data64[6] * XXH64_PRIME_2);
                __asm__("ROR %[num3], %[num3], %[shift]" : [num3] "+r"(num3) : [shift] "r"(shiftRight)); 
                num3 *= XXH64_PRIME_1;

                num4 += (uint64_t)(data64[7] * XXH64_PRIME_2);
                __asm__("ROR %[num4], %[num4], %[shift]" : [num4] "+r"(num4) : [shift] "r"(shiftRight)); 
                num4 *= XXH64_PRIME_1;

    
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

}
