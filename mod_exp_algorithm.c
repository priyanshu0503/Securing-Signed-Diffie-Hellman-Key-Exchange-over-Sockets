/*********************************************************

FAST MODULAR EXPONENTIATION ALGORITHM
File: mod_exp_algorithm.c
Due: 10/9/2024

*********************************************************/
#include "mod_exp_algorithm.h"

//Fast modular exponentiation algorithm
long long int fast_mod_exp(long long int base,long long int exp, long long int mod)
{
	long long int result = 1;
	base = base % mod;
	while (exp > 0)
	{
		if (exp % 2 == 1)
		{
			result = (result * base) % mod;
		}
		exp /=2;
		base = (base * base) % mod;
	}
	return result;
}