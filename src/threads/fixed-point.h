/* 
Unfortunately, Pintos does not support floating-point arithmetic
in the kernel, This means that calculations on real quantities must
be simulated using integers. The fundamental idea is to treat the rightmost
bits of an integer as representing a Fraction.

Convert n to fixed point:	n * f
Convert x to integer (rounding toward zero):	x / f
Convert x to integer (rounding to nearest):	(x + f / 2) / f if x >= 0,
(x - f / 2) / f if x <= 0.
Add x and y:	x + y
Subtract y from x:	x - y
Add x and n:	x + n * f
Subtract n from x:	x - n * f
Multiply x by y:	((int64_t) x) * y / f
Multiply x by n:	x * n
Divide x by y:	((int64_t) x) * f / y
Divide x by n:	x / n
*/

#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#define fp_t int
#define P 17
#define Q 14
#define F 1<<(Q)

#if P + Q != 31
#error "FATAL ERROR: P + Q != 31."
#endif

#define FIXED_INT_ADD(x, n) (x) + (n) * (F)
#define FIXED_INT_SUBTRACT(x, n) (x) - (n) * (F)
#define FIXED_INT_DIVIDE(x, n) (x) / (n)
#define FIXED_INT_MULTIPLY(x, n) (x) * (n)
#define CONVERT_TO_FIXED(x) (x) * (F)
#define FIXED_TO_INT_ROUND_TOWARDS_ZERO(x) (x) / (F)
#define FIXED_TO_INT_ROUND_TOWARDS_NEAR(x) ((x) >= 0 ? ((x) + (F) / 2) / (F) : ((x) - (F) / 2) / (F))
#define FIXED_MULTIPLY(x, y) ((int64_t)(x)) * (y) / (F)
#define FIXED_DIVISION(x, y) ((int64_t)(x)) * (F) / (y)
#define FIXED_ADD(x, y) (x) + (y)
#define FIXED_SUB(x, y) (x) - (y)

#endif
