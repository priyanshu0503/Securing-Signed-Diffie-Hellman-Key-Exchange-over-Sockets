# Securing-Signed-Diffie-Hellman-Key-Exchange-over-Sockets

********************************************************
SIGNED DIFFIE HELLMAN KEY EXCHANGE OVER SOCKETS

********************************************************
FILES INCLUDED:
server.c - main server program that reads from primes.txt, finds p, q, and its public key, communicates with the client, and then calculated the shared key from the clients public key. Then this shared key is used as the key for SDES encryption/decryption

client.c - main client program that communicates with the server, calculates the client's public key, shares it with the server, then uses the servers public key to generate the shared key. Then this shared key is used as the key for SDES encryption/decryption

SDES.c - program that contains all the backend logic and funcitonality of the encryption/decryption. This encludes key generation, swapping, substitution, and permuation

SDES.h - header file that contains all the function declarations and external variables

mod_exp_algorithm.c - program that contains the funciton for fast modular exponentiation

mod_exp_algorithm.h - header file that contains all the funciton declarations and external variables

primes.txt - text file that has a list of primes going up to a substantial number (6000s for this example file). The format of this is "# # # #...", so each number is separated by only one space. The server reads this file and randomly picks a prime, then generates its primitive root

********************************************************
HOW TO COMPILE:
Using gcc from the command line, the server can be compiled as followed:

C:\...filepath...\FolderOfContents> gcc -o SERVER_ server.c SDES.c mod_exp_algorithm.c
C:\...filepath...\FolderOfContents> ./SERVER_

Using gcc from the command line, the client can be compiled as followed:
C:\...filepath...\FolderOfContents> gcc -o CLIENT_ client.c SDES.c mod_exp_algorithm.c
C:\...filepath...\FolderOfContents> ./CLIENT_

********************************************************
NOTES:
-All files must be in the same folder and file path for them to correctly function with one another
-There MUST be a primes.txt file with the exact format described above for the program to correctly function
-The server must be ran first and be in the status "Waiting for a connection..." before the client can join
-The port number on client.c and server.c MUST be the same. The client must also have the server's ip address set in the code. Otherwise no connection will establish
-The client can only encrypt and send messages to the server, and the server can only decrypt and read the messages
