// test_scaling.c
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include "sensitive.h"

// Original helper funcs

int add_one(int val) {
    return val + 1;
}

int compute(int a, int b) {
    int sum = a + b;
    int result = sum * 2;
    return result;
}

int nested_compute(int x) {
    int temp = add_one(x);
    return compute(temp, 10);
}

// One "taint block" - same pattern as test.c

#define TAINT_BLOCK(i)                                       \
    void taint_block_##i(void) {                             \
        sensitive int secret_##i = 0xfeed0000 ^ (i);         \
        int copy_##i       = secret_##i;                     \
        int arithmetic_##i = secret_##i + 100;               \
        int multi_##i      = (secret_##i * 2) - 50;          \
        int boolean_##i    = (secret_##i > 1000) ? 1 : 0;    \
        int result1_##i    = add_one(secret_##i);            \
        int result2_##i    = add_one(copy_##i);              \
        int result3_##i    = compute(secret_##i, 5);         \
        int result4_##i    = nested_compute(secret_##i);     \
        int mixed1_##i     = add_one(arithmetic_##i);        \
        int mixed2_##i     = mixed1_##i * 3;                 \
        int mixed3_##i     = compute(mixed2_##i, result1_##i); \
        volatile int sink = 0;                               \
        sink ^= copy_##i ^ arithmetic_##i ^ multi_##i;       \
        sink ^= boolean_##i ^ result1_##i ^ result2_##i;     \
        sink ^= result3_##i ^ result4_##i;                   \
        sink ^= mixed1_##i ^ mixed2_##i ^ mixed3_##i;        \
        (void)sink;                                          \
    }


#define EXPAND_BLOCKS \
    TAINT_BLOCK(1)  TAINT_BLOCK(2)  TAINT_BLOCK(3)  TAINT_BLOCK(4)  TAINT_BLOCK(5) \
    TAINT_BLOCK(6)  TAINT_BLOCK(7)  TAINT_BLOCK(8)  TAINT_BLOCK(9)  TAINT_BLOCK(10) \
    TAINT_BLOCK(11) TAINT_BLOCK(12) TAINT_BLOCK(13) TAINT_BLOCK(14) TAINT_BLOCK(15) \
    TAINT_BLOCK(16) TAINT_BLOCK(17) TAINT_BLOCK(18) TAINT_BLOCK(19) TAINT_BLOCK(20) \
    TAINT_BLOCK(21) TAINT_BLOCK(22) TAINT_BLOCK(23) TAINT_BLOCK(24) TAINT_BLOCK(25) \
    TAINT_BLOCK(26) TAINT_BLOCK(27) TAINT_BLOCK(28) TAINT_BLOCK(29) TAINT_BLOCK(30) \
    TAINT_BLOCK(31) TAINT_BLOCK(32) TAINT_BLOCK(33) TAINT_BLOCK(34) TAINT_BLOCK(35) \
    TAINT_BLOCK(36) TAINT_BLOCK(37) TAINT_BLOCK(38) TAINT_BLOCK(39) TAINT_BLOCK(40) \
    TAINT_BLOCK(41) TAINT_BLOCK(42) TAINT_BLOCK(43) TAINT_BLOCK(44) TAINT_BLOCK(45) \
    TAINT_BLOCK(46) TAINT_BLOCK(47) TAINT_BLOCK(48) TAINT_BLOCK(49) TAINT_BLOCK(50) \
    TAINT_BLOCK(51) TAINT_BLOCK(52) TAINT_BLOCK(53) TAINT_BLOCK(54) TAINT_BLOCK(55) \
    TAINT_BLOCK(56) TAINT_BLOCK(57) TAINT_BLOCK(58) TAINT_BLOCK(59) TAINT_BLOCK(60) \
    TAINT_BLOCK(61) TAINT_BLOCK(62) TAINT_BLOCK(63) TAINT_BLOCK(64) TAINT_BLOCK(65) \
    TAINT_BLOCK(66) TAINT_BLOCK(67) TAINT_BLOCK(68) TAINT_BLOCK(69) TAINT_BLOCK(70) \
    TAINT_BLOCK(71) TAINT_BLOCK(72) TAINT_BLOCK(73) TAINT_BLOCK(74) TAINT_BLOCK(75) \
    TAINT_BLOCK(76) TAINT_BLOCK(77) TAINT_BLOCK(78) TAINT_BLOCK(79) TAINT_BLOCK(80) \
    TAINT_BLOCK(81) TAINT_BLOCK(82) TAINT_BLOCK(83) TAINT_BLOCK(84) TAINT_BLOCK(85) \
    TAINT_BLOCK(86) TAINT_BLOCK(87) TAINT_BLOCK(88) TAINT_BLOCK(89) TAINT_BLOCK(90) \
    TAINT_BLOCK(91) TAINT_BLOCK(92) TAINT_BLOCK(93) TAINT_BLOCK(94) TAINT_BLOCK(95) \
    TAINT_BLOCK(96) TAINT_BLOCK(97) TAINT_BLOCK(98) TAINT_BLOCK(99) TAINT_BLOCK(100)

EXPAND_BLOCKS

int main(int argc, char *argv[]) {
    printf("Comprehensive Taint Propagation Scaling Test\n");
    int num_blocks = (argc > 1) ? atoi(argv[1]) : 1;
    if (num_blocks < 0) num_blocks = 0;
    if (num_blocks > 100) num_blocks = 100;

    if (num_blocks >= 1) taint_block_1();
    if (num_blocks >= 2) taint_block_2();
    if (num_blocks >= 3) taint_block_3();
    if (num_blocks >= 4) taint_block_4();
    if (num_blocks >= 5) taint_block_5();
    if (num_blocks >= 6) taint_block_6();
    if (num_blocks >= 7) taint_block_7();
    if (num_blocks >= 8) taint_block_8();
    if (num_blocks >= 9) taint_block_9();
    if (num_blocks >= 10) taint_block_10();
    if (num_blocks >= 11) taint_block_11();
    if (num_blocks >= 12) taint_block_12();
    if (num_blocks >= 13) taint_block_13();
    if (num_blocks >= 14) taint_block_14();
    if (num_blocks >= 15) taint_block_15();
    if (num_blocks >= 16) taint_block_16();
    if (num_blocks >= 17) taint_block_17();
    if (num_blocks >= 18) taint_block_18();
    if (num_blocks >= 19) taint_block_19();
    if (num_blocks >= 20) taint_block_20();
    if (num_blocks >= 21) taint_block_21();
    if (num_blocks >= 22) taint_block_22();
    if (num_blocks >= 23) taint_block_23();
    if (num_blocks >= 24) taint_block_24();
    if (num_blocks >= 25) taint_block_25();
    if (num_blocks >= 26) taint_block_26();
    if (num_blocks >= 27) taint_block_27();
    if (num_blocks >= 28) taint_block_28();
    if (num_blocks >= 29) taint_block_29();
    if (num_blocks >= 30) taint_block_30();
    if (num_blocks >= 31) taint_block_31();
    if (num_blocks >= 32) taint_block_32();
    if (num_blocks >= 33) taint_block_33();
    if (num_blocks >= 34) taint_block_34();
    if (num_blocks >= 35) taint_block_35();
    if (num_blocks >= 36) taint_block_36();
    if (num_blocks >= 37) taint_block_37();
    if (num_blocks >= 38) taint_block_38();
    if (num_blocks >= 39) taint_block_39();
    if (num_blocks >= 40) taint_block_40();
    if (num_blocks >= 41) taint_block_41();
    if (num_blocks >= 42) taint_block_42();
    if (num_blocks >= 43) taint_block_43();
    if (num_blocks >= 44) taint_block_44();
    if (num_blocks >= 45) taint_block_45();
    if (num_blocks >= 46) taint_block_46();
    if (num_blocks >= 47) taint_block_47();
    if (num_blocks >= 48) taint_block_48();
    if (num_blocks >= 49) taint_block_49();
    if (num_blocks >= 50) taint_block_50();
    if (num_blocks >= 51) taint_block_51();
    if (num_blocks >= 52) taint_block_52();
    if (num_blocks >= 53) taint_block_53();
    if (num_blocks >= 54) taint_block_54();
    if (num_blocks >= 55) taint_block_55();
    if (num_blocks >= 56) taint_block_56();
    if (num_blocks >= 57) taint_block_57();
    if (num_blocks >= 58) taint_block_58();
    if (num_blocks >= 59) taint_block_59();
    if (num_blocks >= 60) taint_block_60();
    if (num_blocks >= 61) taint_block_61();
    if (num_blocks >= 62) taint_block_62();
    if (num_blocks >= 63) taint_block_63();
    if (num_blocks >= 64) taint_block_64();
    if (num_blocks >= 65) taint_block_65();
    if (num_blocks >= 66) taint_block_66();
    if (num_blocks >= 67) taint_block_67();
    if (num_blocks >= 68) taint_block_68();
    if (num_blocks >= 69) taint_block_69();
    if (num_blocks >= 70) taint_block_70();
    if (num_blocks >= 71) taint_block_71();
    if (num_blocks >= 72) taint_block_72();
    if (num_blocks >= 73) taint_block_73();
    if (num_blocks >= 74) taint_block_74();
    if (num_blocks >= 75) taint_block_75();
    if (num_blocks >= 76) taint_block_76();
    if (num_blocks >= 77) taint_block_77();
    if (num_blocks >= 78) taint_block_78();
    if (num_blocks >= 79) taint_block_79();
    if (num_blocks >= 80) taint_block_80();
    if (num_blocks >= 81) taint_block_81();
    if (num_blocks >= 82) taint_block_82();
    if (num_blocks >= 83) taint_block_83();
    if (num_blocks >= 84) taint_block_84();
    if (num_blocks >= 85) taint_block_85();
    if (num_blocks >= 86) taint_block_86();
    if (num_blocks >= 87) taint_block_87();
    if (num_blocks >= 88) taint_block_88();
    if (num_blocks >= 89) taint_block_89();
    if (num_blocks >= 90) taint_block_90(); 
    if (num_blocks >= 91) taint_block_91();
    if (num_blocks >= 92) taint_block_92();
    if (num_blocks >= 93) taint_block_93();
    if (num_blocks >= 94) taint_block_94();
    if (num_blocks >= 95) taint_block_95();
    if (num_blocks >= 96) taint_block_96();
    if (num_blocks >= 97) taint_block_97();
    if (num_blocks >= 98) taint_block_98();
    if (num_blocks >= 99) taint_block_99();
    if (num_blocks >= 100) taint_block_100();
    return 0;
    

}