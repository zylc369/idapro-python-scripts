/**
 * Function: calculate(double a, double b, char op)
 * Mangled:  __Z9calculateddc
 * Address:  0x100000D98 - 0x100000EA4 (268 bytes)
 * Callers:  _main (0x100000F10), _main (0x100000F34)
 * Arch:     AArch64 (ARM64)
 */

#include <stdio.h>

double calculate(double a, double b, char op) {
    printf("[calculate] a=%lf,b=%lf,op=%c\n", a, b, op);

    double result;

    if (op == '+') {
        result = a + b;
    } else if (op == '-') {
        result = a - b;
    } else if (op == '*') {
        result = a * b;
    } else if (op == '/') {
        if (b == 0.0) {
            result = -1.0;
        } else {
            result = a / b;
        }
    } else {
        result = -1.0;
    }

    return result;
}
