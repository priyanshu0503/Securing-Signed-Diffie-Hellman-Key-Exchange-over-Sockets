/****************************************************

Header file for RSA algorithm

*****************************************************/

#ifndef RSA_ALGORITHM_H
#define RSA_ALGORITHM_H

#include <stdio.h>
#include <math.h>
#include "RSA_algorithm.h"
#include "mod_exp_algorithm.h"

//Function declarations
int is_prime(unsigned int num);
int extended_gcd(unsigned int a, unsigned int b, unsigned int *x, unsigned int *y);
int multiplicative_inverse(unsigned int totient_n, unsigned int x);
void generate_public_key(unsigned int p, unsigned int q, unsigned int e, unsigned int *public_key);
int generate_private_key(unsigned int p, unsigned int q, unsigned int e, unsigned int *private_key);


#endif // RSA_algorithm_H
