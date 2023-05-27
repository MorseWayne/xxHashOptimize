// #include "securec.h" /* 提供 memcpy_s 等安全函数，Windows 平台上不需要此头文件 */
#include "sgl.h" /* 包含了 SGL 结构体的定义以及 SGL_HashValue 的声明。 */
#include <stdbool.h>
#include <arm_neon.h>
#include <string.h>

#define XXH64_LANE_COUNT ((size_t)4)
#define XXH64_SEED ((uint64_t)0)
#define XXH64_STEP_SIZE ((size_t)32)

#define XXH64_PRIME_1 ((uint64_t)0x9E3779B185EBCA87ULL)
#define XXH64_PRIME_2 ((uint64_t)0xC2B2AE3D27D4EB4FULL)
#define XXH64_PRIME_3 ((uint64_t)0x165667B19E3779F9ULL)
#define XXH64_PRIME_4 ((uint64_t)0x85EBCA77C2B2AE63ULL)
#define XXH64_PRIME_5 ((uint64_t)0x27D4EB2F165667C5ULL)

#define ROTATE_LEFT(value, shift) (value << shift) | (value >> (64 - shift))

/*
 * 用于保存 XXH64 算法的状态。
 */
typedef struct
{
    uint64_t acc[XXH64_LANE_COUNT];  /* 4 个累加器。 */
    uint8_t buffer[XXH64_STEP_SIZE]; /* 保存不满 32 字节的零散数据。 */
    size_t bufferSize;               /* 当前零散数据的大小。 */
    uint64_t totalSize;              /* 状态已经接受的数据的总大小。 */
    bool isLarge;                    /* 状态是否已经接受了大于 32 字节的数据量。 */
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

    for (size_t i = 0; i < XXH64_LANE_COUNT; i++)
    {
        finalAcc = XXH64_MergeAccumulator(finalAcc, state->acc[i]);
    }

    finalAcc += (uint64_t)state->totalSize;
    return finalAcc;
}

/* 对 finalAcc 进行雪崩操作、使得输入发生微小变动时，输出的每一位都有机会被翻转。 */
static inline uint64_t XXH64_Mix(uint64_t finalAcc)
{
    const int MIX_COUNT = 3;
    const int MIX_SHIFT[] = {33, 29, 32};
    const uint64_t MIX_MUL[] = {XXH64_PRIME_2, XXH64_PRIME_3, 1};
    uint64_t tmp = finalAcc;
    for (size_t i = 0; i < MIX_COUNT; i++)
    {
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

uint64_t SGL_HashValue(SGL *sgl)
{

    // XXH64_StateInit(&state);
    // memset(&state,0,sizeof(state));
    uint64_t num1 = 0x60ea27eeadc0b5d6;
    uint64_t num2 = 0xc2b2ae3d27d4eb4f;
    uint64_t num3 = 0;
    uint64_t num4 = 0x61c8864e7a143579;
   

    for (size_t i = 0; i < sgl->entryCount; i++)
    {
        const uint8_t *entrybuf = sgl->entries[i].buf;
        size_t entrylen = sgl->entries[i].len;
        // __builtin_prefetch(entrybuf + 520);
        for (size_t offset = 0; offset < entrylen; offset += 520)
        {
            // process current block
            // XXH64_Update_new(&state, entrybuf + offset, BYTE_PER_SECTOR_NOPI);
            const uint64_t *data64 = (uint64_t *)(entrybuf + offset);

            for (size_t i = 0; i < 16; ++i)
            {
                uint64_t data1;
                uint64_t data2;
                uint64_t data3;
                uint64_t data4;
                uint64_t prime1;
                uint64_t prime2;

                asm(
                    // load prime1
                    "mov %x[prime1], 0xca87\n\t"
                    "movk %x[prime1], 0x85eb, lsl 16\n\t"
                    "movk %x[prime1], 0x79b1, lsl 32\n\t"
                    "movk %x[prime1], 0x9e37, lsl 48\n\t"
                    : [prime1] "=r"(prime1));

                asm(
                    // load prime1
                    "mov %x[prime2], 0xEB4F\n\t"
                    "movk %x[prime2], 0x27D4, lsl 16\n\t"
                    "movk %x[prime2], 0xAE3D, lsl 32\n\t"
                    "movk %x[prime2], 0xC2B2, lsl 48\n\t"
                    : [prime2] "=r"(prime2));
                asm(
                    // load data from address
                    "ldp %x[data1], %x[data2], [%[address]]\n\t"
                    "ldp %x[data3], %x[data4], [%[address], #16]\n\t"
                    : [data1] "=r"(data1), [data2] "=r"(data2), [data3] "=r"(data3), [data4] "=r"(data4)
                    : [address] "r"(data64));

                asm(
                    "madd %[num1], %[data1], %[prime2], %[num1]\n\t"
                    "madd %[num2], %[data2], %[prime2], %[num1]\n\t"
                    "madd %[num3], %[data3], %[prime2], %[num1]\n\t"
                    "madd %[num4], %[data4], %[prime2], %[num1]\n\t"
                    : [num1] "+r"(num1), [num2] "=r"(num2), [num3] "=r"(num3), [num4] "=r"(num4), [data1] "=r"(data1), [data2] "=r"(data2), [data3] "=r"(data3), [data4] "=r"(data4)
                    : [prime2] "r"(prime2));

                num1 = (num1 << 31 | num1 >> 33);
                num2 = (num2 << 31 | num2 >> 33);
                num3 = (num3 << 31 | num3 >> 33);
                num4 = (num4 << 31 | num4 >> 33);

                asm(
                    "madd %[num1], %[num1], %[prime1], %[num1]\n\t"
                    "madd %[num2], %[num2], %[prime1], %[num2]\n\t"
                    "madd %[num3], %[num3], %[prime1], %[num3]\n\t"
                    "madd %[num4], %[num4], %[prime1], %[num4]\n\t"
                    : [num1] "+r"(num1), [num2] "=r"(num2), [num3] "=r"(num3), [num4] "=r"(num4)
                    : [prime1] "r"(prime1));

                data64 += 4;
            }
        }
    }

    XXH64State state = {};
    state.totalSize = sgl->entryCount * 8192;
    state.acc[0] = num1;
    state.acc[1] = num2;
    state.acc[2] = num3;
    state.acc[3] = num4;

    return XXH64_Digest(&state);
}

#include <iostream>
#include "xxhash.h"
using namespace std;

// uint64_t SGL_HashValue_Raw(SGL *sgl)
// {
//     XXH64_state_t *state = XXH64_createState();
//     XXH64_reset(state, 0);
//     for (size_t i = 0; i < sgl->entryCount; i++) {
//         const uint8_t *entrybuf = sgl->entries[i].buf;
//         size_t entrylen = sgl->entries[i].len;
//         for (size_t offset = 0; offset < entrylen; offset += BYTE_PER_SECTOR_PI) {
//             // prefetch the next block
//             // __builtin_prefetch(entrybuf + offset + BYTE_PER_SECTOR_PI);

//             // process current block
//             XXH64_update(state, entrybuf + offset, BYTE_PER_SECTOR_NOPI);
//         }
//     }
//     return XXH64_digest(state);
// }

#include <iostream>
#include <vector>
#include <random>
#include <algorithm>
#include <chrono>

void generate()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);

    const int contentSize = 8320;

    std::vector<char> randomContent(contentSize);
    std::generate_n(randomContent.begin(), contentSize, [&]()
                    { return static_cast<char>(dis(gen)); });
}

constexpr uint32_t DATA_LEN = 8320;
uint64_t Test(SGL sgl)
{
    // std::random_device rd;
    // std::mt19937 gen(rd());
    // std::uniform_int_distribution<int> dis(0, 255);

    // static std::vector<char> randomContent(DATA_LEN);
    // std::generate_n(randomContent.begin(), DATA_LEN, [&]()
    //                 { return static_cast<char>(dis(gen)); });

    // std::copy(randomContent.begin(), randomContent.end(), sgl.entries[0].buf);

    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < 10000; i++)
    {
        SGL_HashValue(&sgl);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    // std::cout << "time cost: " << duration.count() << " us" << std::endl;
    return duration.count();
}

int main()
{
    SGL sgl;

    sgl.entries[0].buf = new uint8_t[DATA_LEN]();
    sgl.entries[0].len = DATA_LEN;

    sgl.entryCount = 1;

    uint64_t expected = 0x2b5073505a48fb4;
    // auto ret = SGL_HashValue_Raw(&sgl);
    // if (expected != ret) {
    //     cout << "[raw implenment] incorrect!" << endl;
    // }

    auto ret = SGL_HashValue(&sgl);
    if (expected != ret)
    {
        cout << "[my implenment] incorrect!" << endl;
    }

    uint64_t totalCostTimes = 0;
    for (size_t i = 0; i < 10000; i++)
    {
        totalCostTimes += Test(sgl);
    }
    std::cout << "time cost: " << totalCostTimes << " us" << std::endl;
}
