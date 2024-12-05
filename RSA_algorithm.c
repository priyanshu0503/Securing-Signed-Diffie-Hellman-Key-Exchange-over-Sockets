/*******************************************************************************

This file contains the implementation of the RSA algorithm functions.

*********************************************************/
#include <stdio.h>
#include <math.h>
#include "RSA_algorithm.h"
#include "mod_exp_algorithm.h"

//This function checks if a number is prime 
int is_prime(unsigned int num) {
    if (num <= 1) {
        return 0; // 0 and 1 are not prime
    }
    for (unsigned int i = 2; i <= sqrt(num); i++) {
        if (num % i == 0) {
            return 0; // If divisible by any number other than 1 and itself, not prime
        }
    }
    return 1; // Prime number
}

//Function to perform the Extended Euclidean Algorithm
//Returns the gcd of a and b, and updates x and y such that ax + by = gcd(a, b)
int extended_gcd(unsigned int a, unsigned int b, unsigned int *x, unsigned int *y)
{
    if (a == 0) {
        *x = 0;
        *y = 1;
        return b;
    }

    //To store results of recursive call
    unsigned int x1, y1;
    int gcd = extended_gcd(b % a, a, &x1, &y1);

    *x = y1 - (b / a) * x1;
    *y = x1;

    return gcd;
}

//Function to find a multiplicative inverse of x mod totient_n
int multiplicative_inverse(unsigned int totient_n, unsigned int x) {
    unsigned int inverse, temp;

    //if x is less than or equal to 0 or greater than or equal to the totient of n
    if (x <= 0 || x >= totient_n) {
        return -1;
    }

    int gcd = extended_gcd(x, totient_n, &inverse, &temp);

    //If gcd is not 1, the inverse does not exist
    if (gcd != 1)
    {
        return -1;
    }
    //Ensure the inverse is positive by taking mod totient_n
    else if (inverse < 0)
    {
        inverse += totient_n;
        return inverse;
    }
    else
    {
    return inverse;
    }
}

// Function to calculate and return the public key
// The public key consists of (e, n)
void generate_public_key(unsigned int p, unsigned int q, unsigned int e, unsigned int *public_key)
{
    unsigned int n = p * q;

    // Set the public key
    public_key[0] = e;
    public_key[1] = n;
}

// Function to calculate and return the private key
// The private key consists of (d, n)
int generate_private_key(unsigned int p, unsigned int q, unsigned int e, unsigned int *private_key)
{
    unsigned int n = p * q;
    unsigned int totient_n = (p - 1) * (q - 1);

    // Check if e is relatively prime to totient_n
    if (extended_gcd(e, totient_n, &p, &q) != 1) {
        return -1; // e is not relatively prime to totient_n
    }

    // Calculate the multiplicative inverse (private key component d)
    int d = multiplicative_inverse(totient_n, e);
    if (d == -1) {
        return -1; // No multiplicative inverse
    }

    // Set the private key
    private_key[0] = d;
    private_key[1] = n;

    return 0; // Successful private key generation
}



