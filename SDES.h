/*********************************************************
SDES Encryption/Decryption - CSC 487

*********************************************************/
#ifndef SDES_H
#define SDES_H

//function declarations
long long int fast_mod_exp(long long int base, long long int exp, long long int mod);
void shift(int ar[], int size, int shifts);
void key_generation(int key[]);
int* function_(int ar[], int key[]);
int* encryption(int plaintext[]);
int* decryption(int ar[]);
char* binary_(int val);

extern int key[];
extern int P10[];
extern int P8[];
extern int key1[];
extern int key2[];
extern int IP[];
extern int EP[];
extern int P4[];
extern int IP_inv[];
extern int S0[][4];
extern int S1[][4];



#endif // SDES_H
