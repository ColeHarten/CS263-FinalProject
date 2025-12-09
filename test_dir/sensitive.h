#define sensitive __attribute__((annotate("sensitive"))) volatile

// #define SENSITIVE_BARRIER(var) \ 
//         do { \ 
//             __asm__ volatile ("" : : "m" (var) : "memory"); \ 
//         } while(0)