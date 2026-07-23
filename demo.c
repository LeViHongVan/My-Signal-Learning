#include <stdio.h>
#include <stdlib.h>
#include "src/signal_protocol.h"
#include "src/curve.h"

int main() {
    printf("=====================================================\n");
    printf("  DEMO LIBSIGNAL PROTOCOL C - VERIFYING ALGORITHMS   \n");
    printf("=====================================================\n\n");

    printf("[1] Chay kiem tra thuat toan Curve25519 Elliptic Curve...\n");
    int result = curve_internal_fast_tests(0);
    if (result == 0) {
        printf("    -> THUAT TOAN CURVE25519 CHAY THANH CONG! (Result = 0)\n");
    } else {
        printf("    -> THUAT TOAN CURVE25519 THAT BAI! (Result = %d)\n", result);
    }

    printf("\n=====================================================\n");
    printf("  HOAN THANH CHAY DEMO THUAT TOAN SIGNAL PROTOCOL    \n");
    printf("=====================================================\n");
    return 0;
}
