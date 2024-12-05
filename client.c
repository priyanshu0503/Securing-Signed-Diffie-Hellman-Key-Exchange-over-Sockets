/*********************************************************

Credits to Fourney's sockets client/server example in c
*********************************************************/
#include<stdio.h>      // used printf/scanf for demo (puts/getchar would be leaner)
#include<string.h>  
#include<sys/socket.h>
#include<arpa/inet.h>  // for inet_addr and sockaddr_in structs
#include<stdlib.h>
#include<unistd.h>
#include"SDES.h"
#include "mod_exp_algorithm.h"


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

//Function to convert a character to 8-bit binary
void charToBinary(char character, int *binaryArray)
{
   for (int i = 7; i >= 0; i--)
   {
       binaryArray[i] = character % 2;
       character /= 2;
   }
}

//Main Function
int main(int argc , char *argv[])
{
  int socket_desc;    // file descripter returned by socket command
  int read_size;
  struct sockaddr_in server;    // in arpa/inet.h
  char  server_reply[100], client_message[100];  
  
  
  //Create socket
  socket_desc = socket(AF_INET , SOCK_STREAM , 0);

  printf("Trying to create socket\n");
  if (socket_desc == -1)
  {
      printf("Unable to create socket\n");
  }
      
// *********** This is the line you need to edit ****************
  server.sin_addr.s_addr = inet_addr("169.254.216.26"); 
  server.sin_family = AF_INET;
  server.sin_port = htons( 8439);    // random "high"  port number

  //Connect to remote server
  if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
  {
      printf(" connect error");
      return 1;
  }

  //Recieve server's public key
  if(recv(socket_desc , server_reply , 100 , 0) < 0)
  {
      printf("receive failed\n");
  }

  //Scan p, g, and the server's public key. Print to console
  long long int p,g, public_key_server;
  sscanf(server_reply, "%lld %lld %lld", &p, &g, &public_key_server);
  printf("Received p,g,servers_public_key %lld %lld %lld\n", p,g, public_key_server);

   //Generate a private key and calculate the client's public key
  //Create servers private key and generate the public key to send to client
  long long int private_key_client = 0;// = rand()%1000; //Server's private key less than 1000

  printf("Please enter a private key number between 1 and 1000.");
  
  do
  {
      scanf("%lld", &private_key_client);
      if(private_key_client <= 0 || private_key_client > 1000)
      {
          printf("Please enter a valid number between 1 and 1000");
      }
  } while (private_key_client <= 0 || private_key_client > 1000);

  long long int public_key_client = fast_mod_exp(g, private_key_client, p); //Client's public key
  printf("private_key & public_key %lld %lld\n", private_key_client, public_key_client);

  //Send client's public key to server
  char client_public_key[15];
  snprintf(client_public_key, 15, "%lld", public_key_client);
  if(send(socket_desc , client_public_key , strlen(client_public_key) , 0) < 0)
  {
      printf("send failed\n");
      return 1;
  }

  //Compute shared key
  long long int shared_key = fast_mod_exp(public_key_server, private_key_client, p);
  printf("Shared Key (client): %lld\n", shared_key);

  //Use shared key as SDES KEY
 int size = 10;
 int * shared_key_binary = malloc(size*sizeof(int));

 if (shared_key_binary == NULL) {
     perror("Failed to allocate memory");
     return 1;
 }

   //Convert to correct type
 longLongToBinary(shared_key, shared_key_binary, size);

 //Print the binary representation
 printf("Binary representation of %lld is: ", shared_key);
 for (int i = 0; i < size; i++) {
     printf("%d", shared_key_binary[i]);
 }
 printf("\n");

 key_generation(shared_key_binary);



 while(1)  // infinite loop to keep sending messages
  {
      // Read the entire message from input
      memset(client_message, '\0', 100);
      fgets(client_message, 100, stdin);

      // Break if message is "b" or "bye"
      if (strncmp(client_message, "b", 1) == 0) {
          break;
      }
 
      // Process each character in the message
      for (int j = 0; j < strlen(client_message); j++) {
          // Convert character to binary
          int plaintext[8];
          charToBinary(client_message[j], plaintext);

          // Encrypt the 8-bit binary character
          int* ciphertext = encryption(plaintext);

          // Prepare the encrypted binary to send (as characters)
          char encrypted_char[9];
          for (int i = 0; i < 8; i++) {
              encrypted_char[i] = ciphertext[i] + '0';  // Convert 0/1 to '0'/'1'
          }
          encrypted_char[8] = '\0';  // Null-terminate the string

          // Send encrypted character to the server
          if (send(socket_desc, encrypted_char, 8, 0) < 0) {
              printf("Send failed\n");
              return 1;
          }

          printf("Encrypted character sent to server: %s\n", encrypted_char);
      }
  }
  //Close the socket connection and program
  close(socket_desc);
  return 0;
}


