#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include "sensitive.h"

// Test interprocedural taint: simple function
int add_one(int val) {
    return val + 1;
}

// Test interprocedural taint: function with multiple operations
int compute(int a, int b) {
    int sum = a + b;
    int result = sum * 2;
    return result;
}

// Test interprocedural taint: nested calls
int nested_compute(int x) {
    int temp = add_one(x);
    return compute(temp, 10);
}

int main() {    
    printf("Comprehensive Taint Propagation Test\n");
    
    // Explicit sensitive variable
    sensitive int secret = 0xfeedbeef;
    printf("1. Explicit sensitive: secret = 0x%x\n", secret);
    
    // intraprocedural taint (phasar should handle)
    printf("\nIntraprocedural Taint (PhASAR)\n");
    
    // Test 1: Direct assignment
    int copy = secret;
    printf("2. Direct assignment: copy = secret = 0x%x\n", copy);
    
    // Test 2: Arithmetic operations
    int arithmetic = secret + 100;
    printf("3. Arithmetic: arithmetic = secret + 100 = 0x%x\n", arithmetic);
    
    // Test 3: Multiple operations
    int multi = (secret * 2) - 50;
    printf("4. Multi-op: multi = (secret * 2) - 50 = 0x%x\n", multi);
    
    // Test 4: Boolean operations
    int boolean = (secret > 1000) ? 1 : 0;
    printf("5. Boolean: boolean = (secret > 1000) = %d\n", boolean);
    
    // interprocedural taint (custom should handle) ===
    printf("\nInterprocedural Taint (Custom)\n");
    
    // Test 5: Simple function call
    int result1 = add_one(secret);
    printf("6. Function call: result1 = add_one(secret) = 0x%x\n", result1);
    
    // Test 6: Function with tainted derived value
    int result2 = add_one(copy);
    printf("7. Derived arg: result2 = add_one(copy) = 0x%x\n", result2);
    
    // Test 7: Function with multiple arguments
    int result3 = compute(secret, 5);
    printf("8. Multi-arg: result3 = compute(secret, 5) = 0x%x\n", result3);
    
    // Test 8: Nested function calls
    int result4 = nested_compute(secret);
    printf("9. Nested: result4 = nested_compute(secret) = 0x%x\n", result4);
    
    // Test 9: Mix intra + inter
    int mixed1 = add_one(arithmetic);
    int mixed2 = mixed1 * 3;
    int mixed3 = compute(mixed2, result1);
    printf("10. Mixed: mixed3 = compute(mixed2, result1) = 0x%x\n", mixed3);
    
    printf("\nTest Complete\n");    
    return 0;
}