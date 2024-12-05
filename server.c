/*********************************************************

Credits to Fourney's sockets client/server example in c
*********************************************************/
#include<stdio.h>
#include<string.h>	//strlen
#include<sys/socket.h>
#include<arpa/inet.h>	//inet_addr
#include<unistd.h>	//write
#include<stdlib.h>	// for system & others
#include<time.h>
#include<math.h>
#include "SDES.h"
#include "mod_exp_algorithm.h"
#include "RSA_algorithm.h"

//Funciton to calculate the gcd
int gcd(int a, int b)
{
    while (b)
    {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

//Function for modular exponentiation (regular integer, not long long int)
int modular_exponentiation(long long base, long long exp, long long mod)
{
    long long result = 1;
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

//Function to check if a number is the primitite root of a prime
int is_primitive_root(int n, int p, int *factors, int num_factors)
{
    for (int i = 0; i < num_factors; i++)
    {
        //if n^((p-1)/factor) % p == 1, n is NOT a primitive root
        if (modular_exponentiation(n, (p - 1) / factors[i], p) == 1)
        {
            return 0;
        }
    }
    return 1; //n is a primitive root
}

// Function to find the factors of p-1
int find_factors(int p, int *factors)
{
    int num_factors = 0;
    int n = p - 1;

    for (int i = 2; i * i <= n; i++)
    {
        while (n % i == 0)
        {
            factors[num_factors++] = i;
            n /= i;
        }
    }
    //if n > 1, add remaining prime factor
    if (n > 1)
    {
        factors[num_factors++] = n;
    }

    return num_factors;
}

//Function to find a primitive root of a given prime p
int find_primitive_root(int p)
{
    int *factors = malloc((p - 1) * sizeof(int));
    int num_factors = find_factors(p, factors);

    for (int g = 2; g < p; g++)
    {
        //if g is primitive, return it
        if (is_primitive_root(g, p, factors, num_factors))
        {
            free(factors);
            return g;
        }
    }
	free(factors);
	return -1;
}

//Function to convert long long int to binary
void longLongToBinary(long long int number, int *binaryArray, int size)
{
    for (int i = size - 1; i >= 0; i--)
    {
        //find the least significant bit and divide by 2 to shift right
        binaryArray[i] = number % 2;
        number /= 2;                
    }
}

char binaryToChar(int *binaryArray)
{
    char character = 0;
    for (int i = 0; i < 8; i++) {
        character = (character << 1) | binaryArray[i];  // Shift left and add current bit
    }
    return character;
}
//***************************************************************************************************************
//Main Function
int main(int argc , char *argv[])
{
	//Variables that will be used
	FILE *file;

    //Open the file
    file = fopen("Primes.txt", "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    int count = 0;
    char line[256];
    while (fgets(line, sizeof(line), file))
    {
        count++;
    }
    //Generate a random index
    srand(time(NULL));
    int random_index = rand() % count;

    // Rewind the file to read the random prime and g
    rewind(file);
    int current_index = 0;
    long long int p = 0;
    long long int g = 0;

    // Read until the random index is reached
    while (fgets(line, sizeof(line), file)) {
        if (current_index == random_index) {
            char *token = strtok(line, " ");
            p = atoll(token); // Read the prime number
            token = strtok(NULL, " ");
            g = atoll(token); // Read the corresponding g
            printf("Random prime: %lld, Primitive root: %lld\n", p, g);
            break; // Break out of the loop once we find our random index
        }
        current_index++;
    }

    // Close the file
    fclose(file);
//***************************************************************************************************************



    unsigned int pr, q, e; //Use unsigned int for larger prime numbers

    do {
        printf("Please enter p (a large prime number): ");
        scanf("%u", &pr);
        // Check if p is prime
        if (!is_prime(pr)) {
            printf("Error: p is not a prime number. Please try again.\n");
        }
    } while (!is_prime(pr));

    do {
        printf("Please enter q (a large prime number): ");
        scanf("%u", &q);
        // Check if q is prime
        if (!is_prime(q)) {
            printf("Error: q is not a prime number. Please try again.\n");
        }
    } while (!is_prime(q));

    //Calculate n and the totient of n
    int n = pr * q;
    unsigned int totient_n = (pr - 1) * (q - 1);

    printf("Please enter e (relatively prime to both p and q and less than %u):\n", totient_n);
    printf("A good number for e would be 3, 5, or 7\n");
    

    //Check if e is relatively prime to both p and q
    do{
        scanf("%u", &e);
        if (extended_gcd(e, totient_n, &pr, &q) != 1)
        {
            printf("Error: e must be relatively prime to Totient(n).\n");
        }
    } while(extended_gcd(e, totient_n, &pr, &q) != 1);

    int multiplicative_inv = multiplicative_inverse(totient_n, e);
    
    if (multiplicative_inv == -1)
    {
        printf("Error: No multiplicative inverse exists for %u.\n", e);
    } else if (multiplicative_inv < -1)
    {
        //Adjust the multiplicative inverse so it is positive and less than the totient of n
        multiplicative_inv += totient_n;
        printf("Multiplicative inverse (d): %d\n", multiplicative_inv);
    }else
    {
        printf("Multiplicative inverse (d): %d\n", multiplicative_inv);
    }
    //rename multiplicative_inv to d
    unsigned int d = multiplicative_inv;


    unsigned int rsa_public_key[2] = {e, n};
    printf("Public key: {%u, %u}\n", rsa_public_key[0], rsa_public_key[1]);
    unsigned int rsa_private_key[2] = {d, n};
    printf("Private key: {%u, %u}\n", rsa_private_key[0], rsa_private_key[1]);

//***************************************************************************************************************
    //Create socket
	int socket_desc , new_socket , c, read_size, i;
	struct sockaddr_in server , client;
	char *message, client_message[100];

    //Create servers private key and generate the public key to send to client
	long long int private_key_server = 0;// = rand()%1000; //Server's private key less than 1000

    printf("Please enter a private key number between 1 and 1000.");
    
    do
    {
        scanf("%lld", &private_key_server);
        if(private_key_server <= 0 || private_key_server > 1000)
        {
            printf("Please enter a valid number between 1 and 1000");
        }
    } while (private_key_server <= 0 || private_key_server > 1000);
    

	printf("PRIVATE KEY: %lld\n", private_key_server);
	long long int public_key_server = fast_mod_exp(g, private_key_server, p); //Server's public key
	printf("PUBLIC KEY: %lld\n", public_key_server);

	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1)
	{
		printf("Could not create socket");
	}


    long long int d_ = d;

    long long int RSA_p, RSA_g, RSA_public_key_server;
    //printf("p, d_, and n: %lld, %lld, %lld", p, d_, n);
    RSA_p = fast_mod_exp(p, d_, n);
    RSA_g = fast_mod_exp(g, d_, n);
    RSA_public_key_server = fast_mod_exp(public_key_server, d_, n);

    printf("RSA_p, RSA_g, and RSA_public_key_server: %lld, %lld, %lld\n", RSA_p, RSA_g, RSA_public_key_server);
	
//****************************************************************************************************************
	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( 8439 );  // Random high (assumed unused) port
//****************************************************************************************************************


	//Bind
	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		printf(" unable to bind\n");
		return 1;
	}
	printf(" socket bound, ready for and waiting on a client\n");
	
	//Listen
	listen(socket_desc , 3);
	
	//Accept incoming connection
	printf(" Waiting for incoming connections... \n");
	
	c = sizeof(struct sockaddr_in);
	new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
	if (new_socket<0)
	{
		perror("accept failed");
		return 1;
	}
	
	printf("Connection accepted\n");

 
    //Send RSA public key (e) to client
    char e_[10];
    char n_[10];
    snprintf(e_, sizeof(e_), "%u\n", e); // Sending 'e'
    write(new_socket, e_, strlen(e_));
    printf("Sent RSA public key 'e' to client: %s\n", e_);

    // Step 2: Send RSA public key (n) to client
    snprintf(n_, sizeof(n_), "%u\n", n); // Sending 'n'
    write(new_socket, n_, strlen(n_));
    printf("Sent RSA public key 'n' to client: %s\n", n_);


    /*
    long long int d_ = d;

    long long int RSA_p, RSA_g, RSA_public_key_server;
    RSA_p = fast_mod_exp(p, d_, n);
    RSA_g = fast_mod_exp(g, d_, n);
    RSA_public_key_server = fast_mod_exp(public_key_server, d_, n);

    printf("RSA_p, RSA_g, and RSA_public_key_server: %lld, %lld, %lld\n", RSA_p, RSA_g, RSA_public_key_server);
	*/
	//Sending server's public key to client
	char server_public_key[100];
	snprintf(server_public_key, 15, "%lld %lld %lld\n", p, g, public_key_server);
	write(new_socket , server_public_key , strlen(server_public_key));
	printf("Sent p,g and server's public key : %s\n", server_public_key);

	//Receiving client's public key
	memset(client_message, '\0', 100);
	read_size = recv(new_socket , client_message , 100 , 0);
	long long int public_key_client = atoll(client_message);
	printf("Received, client's public key: %lld\n", public_key_client);

	//Calculating shared key
	long long int shared_key = fast_mod_exp(public_key_client, private_key_server, p);
	printf("Shared Key (server): %lld\n", shared_key);

	//Use shared key as SDES KEY
	int size = 10;
	int * shared_key_binary = malloc(size*sizeof(int));

	if (shared_key_binary == NULL) {
        perror("Failed to allocate memory");
        return 1;
    }

    //Convert the shared key to binary
    longLongToBinary(shared_key, shared_key_binary, size);

    //Print the binary representation
    printf("Binary representation of %lld is: ", shared_key);
    for (int i = 0; i < size; i++) {
        printf("%d", shared_key_binary[i]);
    }
    printf("\n");

	key_generation(shared_key_binary);

    


    // Buffer to hold unprocessed bits from previous messages
    char leftover_bits[8] = {0};
    int leftover_size = 0;

    // Receive messages from client
    while ((read_size = recv(new_socket, client_message, sizeof(client_message) - 1, 0)) > 0) {
        client_message[read_size] = '\0';  // Null-terminate the received message

        printf("Encrypted message from client: %s\n", client_message);
        
        // Combine leftover bits from the previous message with the new message
        char message_buffer[300];  // Enough size to handle leftovers + new message
        strcpy(message_buffer, leftover_bits);  // Copy leftover bits
        strcat(message_buffer, client_message);  // Add the new message
        int message_length = strlen(message_buffer);

        // Process each 8-bit block received from the client
        for (int j = 0; j + 8 <= message_length; j += 8) {
            int encrypted_message[8];

            // Convert received character string into binary array
            for (int i = 0; i < 8; i++) {
                encrypted_message[i] = message_buffer[j + i] - '0';
            }

            // Decrypt the 8-bit binary array using SDES
            int *decrypted_message = decryption(encrypted_message);

            // Convert the decrypted binary array back to a character
            char decrypted_char = binaryToChar(decrypted_message);

            // Print the decrypted character
            printf("%c", decrypted_char);
        }
        
        // Store any leftover bits that don't form a full 8-bit block
        leftover_size = message_length % 8;
        strncpy(leftover_bits, &message_buffer[message_length - leftover_size], leftover_size);
        leftover_bits[leftover_size] = '\0';  // Null-terminate
        printf("\n");  // Newline after entire message
    }
   

    if (read_size == 0) {
        printf("Client disconnected\n");
        fflush(stdout);
    } else if (read_size == -1) {
        perror("Receive failed");
    }
		
	//Free the socket pointer and close the program
	close(socket_desc);
	return 0;
	}

