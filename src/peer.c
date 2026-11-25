#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"


// Global variables to be used by both the server and client side of the peer.
Address_t *my_address;

Address_t** network = NULL;
uint32_t peer_count = 0;
pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;


// helper function that returns 1 if it has added a peer and 0 if it hasn't
int add_peer_if_new(Address_t* peer)
{
    pthread_mutex_lock(&network_mutex);

    for (uint32_t i = 0; i < peer_count; i++) { // check if anyone has the same ip + port. if so return 0
        if (strncmp(network[i]->ip, peer->ip, IP_LEN) == 0 && network[i]->port == peer->port) {
            pthread_mutex_unlock(&network_mutex);
            return 0;
        }
    }

    network = realloc(network, (peer_count + 1) * sizeof(Address_t*));
    network[peer_count] = peer;
    peer_count++;

    pthread_mutex_unlock(&network_mutex);
    return 1;
}

/*
 * Send a request message to another peer on the network. Unless this is 
 * specifically an 'inform' message as described in the assignment handout, a 
 * reply will always be expected.
 */
void send_message(Address_t peer_address, int command, 
    char* request_body, int body_length)
{
    fprintf(stdout, "Connecting to server at %s:%d to run command %d\n", 
        peer_address.ip, peer_address.port, command);

    compsys_helper_state_t state;
    char msg_buf[MAX_MSG_LEN];
    FILE* fp;

    // Setup connection. Note that we need to convert our port from an integer
    // to a string
    char port_char[6];
    port_char[5] = '\0';
    sprintf(port_char, "%d", peer_address.port);
    int peer_socket = compsys_helper_open_clientfd(peer_address.ip, port_char);
    compsys_helper_readinitb(&state, peer_socket);

    // Construct a request message and send it to the peer
    struct RequestHeader request_header;
    strncpy(request_header.ip, my_address->ip, IP_LEN);
    memcpy(request_header.signature, my_address->signature, SHA256_HASH_SIZE);
    request_header.port = htonl(my_address->port);
    request_header.command = htonl(command);
    request_header.length = htonl(body_length);
    // Copy the header and body together to the message buffer, then write to 
    // the socket
    memcpy(msg_buf, &request_header, REQUEST_HEADER_LEN);
    memcpy(msg_buf+REQUEST_HEADER_LEN, request_body, body_length);
    compsys_helper_writen(peer_socket, msg_buf, REQUEST_HEADER_LEN+body_length);

    if (command == 3) {
        close(peer_socket);
        return;
    }

    /*
    3: Handing the response to the register message
    Rather than closing immediately we should probably handle a response.
    */

    char reply_header[REPLY_HEADER_LEN];
    char reply_body[MAX_MSG_LEN];
    
    // reading header
    compsys_helper_readnb(&state, reply_header, REPLY_HEADER_LEN);
    uint32_t reply_length = ntohl(*(uint32_t*)&reply_header[0]);
    uint32_t reply_status = ntohl(*(uint32_t*)&reply_header[4]);
    uint32_t block_number = ntohl(*(uint32_t*)&reply_header[8]);
    uint32_t block_count = ntohl(*(uint32_t*)&reply_header[12]);

    hashdata_t block_hash;
    // bruger memcpy fordi uint32_t kun grapper 4 bytes (tror jeg)
    // SHA256_HASH_SIZE er vidst 32 bytes som er det vi har brug for
    memcpy(block_hash, &reply_header[16], SHA256_HASH_SIZE);

    hashdata_t total_hash;
    memcpy(total_hash, &reply_header[48], SHA256_HASH_SIZE);
    
    // for testing
    printf("length=%u status=%u block=%u count=%u\n",
       reply_length, reply_status, block_number, block_count);

    if (reply_length > MAX_MSG_LEN - REPLY_HEADER_LEN) {
        fprintf(stderr, "Reply too long: %u\n", reply_length);
        close(peer_socket);
        return;
    }
    
    // reading body
    hashdata_t body_hash;
    compsys_helper_readnb(&state, reply_body, reply_length);
    get_data_sha(reply_body, body_hash, reply_length, SHA256_HASH_SIZE);

    if (memcmp(body_hash, block_hash, SHA256_HASH_SIZE) != 0) {
        fprintf(stderr, "Hash mismatch\n");
        close(peer_socket);
        return;
    }

    if (reply_status != STATUS_OK) {
        printf("Got status %u: %.*s\n", reply_status, reply_length, reply_body);
        close(peer_socket);
        return;
    }

    int count = reply_length / PEER_ADDR_LEN;

    for (int i = 0; i < count; i++) {
        Address_t *peer = malloc(sizeof(Address_t));
        
        memcpy(peer, reply_body + (i * PEER_ADDR_LEN), PEER_ADDR_LEN);
        peer->port = ntohl(peer->port);

        if (!add_peer_if_new(peer)) {
            free(peer);
        }
    };
    

    close(peer_socket);
}

/*
 * Function to act as thread for all required client interactions. This thread 
 * will be run concurrently with the server_thread. It will start by requesting
 * the IP and port for another peer to connect to. Once both have been provided
 * the thread will register with that peer and expect a response outlining the
 * complete network. The user will then be prompted to provide a file path to
 * retrieve. This file request will be sent to a random peer on the network.
 * This request/retrieve interaction is then repeated forever.
 */ 

 
void* client_thread()
{
    char peer_ip[IP_LEN];
    fprintf(stdout, "Enter peer IP to connect to: ");
    scanf("%16s", peer_ip);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_ip); i<IP_LEN; i++)
    {
        peer_ip[i] = '\0';
    }

    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: ");
    scanf("%16s", peer_port);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_port); i<PORT_STR_LEN; i++)
    {
        peer_port[i] = '\0';
    }

    Address_t peer_address;
    memcpy(peer_address.ip, peer_ip, IP_LEN);
    peer_address.port = atoi(peer_port);

    /*
    2: Sending a first register message
    Here you should probably send a first register message using the 
    send_message function.
    */
    send_message(peer_address, 1, NULL, 0);
    
    while (1) {
    char filename[256];

    printf("Enter filename to retrieve: ");
    scanf("%255s", filename);

    // Select peer and send request

    pthread_mutex_lock(&network_mutex);

    if (peer_count == 0) {
        pthread_mutex_unlock(&network_mutex);
        printf("No peers available\n");
        continue;
    }

    int index = rand() % peer_count;
    Address_t random_peer = *network[index];

    pthread_mutex_unlock(&network_mutex);

    send_message(random_peer, 2, filename, strlen(filename));
}
// You should never see this printed in your finished implementation
printf("Client thread done\n");

    return NULL;
}


void get_signature(char* password, int password_len, char* salt, hashdata_t* hash) {
    char combined[password_len + SALT_LEN + 1];
    

    memcpy(combined, password, password_len);
    memcpy(combined + password_len, salt, SALT_LEN); // + password_len to avoid it being overwritten

    // combined[password_len + SALT_LEN] = '\0';

    get_data_sha(combined, *hash, password_len + SALT_LEN, SHA256_HASH_SIZE);
}

void send_response(uint32_t connfd, uint32_t status, char* response_body, int response_length) {
    char msg_buf[MAX_MSG_LEN];
    hashdata_t body_hash;
    get_data_sha(response_body, body_hash, response_length, SHA256_HASH_SIZE);

    int32_t network_length = htonl(response_length);
    uint32_t network_status = htonl(status);
    uint32_t network_block_number = htonl(0);
    uint32_t network_block_count = htonl(1);

    memcpy(msg_buf + 0,  &network_length, 4);
    memcpy(msg_buf + 4,  &network_status, 4);
    memcpy(msg_buf + 8,  &network_block_number, 4);
    memcpy(msg_buf + 12, &network_block_count, 4);
    memcpy(msg_buf + 16, body_hash, SHA256_HASH_SIZE);
    memcpy(msg_buf + 48, body_hash, SHA256_HASH_SIZE); 

    memcpy(msg_buf + REPLY_HEADER_LEN, response_body, response_length);

    compsys_helper_writen(connfd, msg_buf, REPLY_HEADER_LEN + response_length);
}

void send_error(int connfd, uint32_t status, char* message) {
    fprintf(stderr, "Error %u: %s\n", status, message);

    // Sender en fejlbesked til klienten
    send_response(connfd, status, message, strlen(message));
}

void handle_inform(char* body, uint32_t length)
{
    if (length != PEER_ADDR_LEN) {
        fprintf(stderr, "Malformed inform\n");
        return;
    }

    Address_t* peer = malloc(sizeof(Address_t));

    memcpy(peer, body, PEER_ADDR_LEN);
    peer->port = ntohl(peer->port);

    if (!add_peer_if_new(peer)) {
        free(peer);
    }
}

void handle_register(int connfd, char* ip, uint32_t port, char* signature)
{
    if (!is_valid_ip(ip)) {
        fprintf(stderr, ">> Invalid peer IP: %s\n", ip);
        return;
    }
    
    if (!is_valid_port(port)) {
        fprintf(stderr, ">> Invalid peer port: %d\n", 
            port);
        return;
    }
    
    Address_t *peer = malloc(sizeof(Address_t));
    memset(peer, 0, sizeof(Address_t));

    // Copy the IP and port
    memcpy(peer->ip, ip, strlen(ip));
    peer->port = port;

    // Generate a random salt for the new peer
    char network_salt[SALT_LEN+1];
    generate_random_salt(network_salt);
    memcpy(peer->salt, network_salt, SALT_LEN);

    // Hash the received signature using the new salt
    get_signature(signature, SHA256_HASH_SIZE, peer->salt, (hashdata_t*)&peer->signature);

    pthread_mutex_lock(&network_mutex);

    for (uint32_t i = 0; i < peer_count; i++) {
        if (strncmp(network[i]->ip, ip, IP_LEN) == 0 && network[i]->port == port) {
            pthread_mutex_unlock(&network_mutex);
            free(peer);
            char* msg = "Peer already in network";
            send_response(connfd, STATUS_PEER_EXISTS, msg, strlen(msg));
            return;
        }
    }

    // Add to the network
    peer_count++;
    network = realloc(network, peer_count * sizeof(Address_t*));
    network[peer_count-1] = peer;

    // step 7
    int list_length = peer_count * PEER_ADDR_LEN;
    char list[list_length];
    for (uint32_t i = 0; i < peer_count; i++) {
        char* p = list + i * PEER_ADDR_LEN;

        memcpy(p + 0, network[i]->ip, IP_LEN); // Copy IP (16 bytes)

        uint32_t net_port = htonl(network[i]->port);
        memcpy(p + 16, &net_port, 4); // Copy port (4 bytes)

        memcpy(p + 20, network[i]->signature, SHA256_HASH_SIZE); // Copy signature (32 bytes)
        memcpy(p + 52, network[i]->salt, SALT_LEN); // Copy salt (16 bytes)
    }

    // Step 8: Inform other peers
    char inform_body[PEER_ADDR_LEN];

    memcpy(inform_body, list + (peer_count - 1) * PEER_ADDR_LEN, PEER_ADDR_LEN);

    Address_t recipients[peer_count];
    int n_recipients = 0;
    for (uint32_t i = 0; i < peer_count; i++) {
        if (network[i] != my_address && network[i] != peer) {
            recipients[n_recipients++] = *network[i];
        }
    }

    pthread_mutex_unlock(&network_mutex);

    // now without the lock
    send_response(connfd, STATUS_OK, list, list_length);
    for (int i = 0; i < n_recipients; i++) {
        send_message(recipients[i], COMMAND_INFORM, inform_body, PEER_ADDR_LEN);
    }
}
/*
 * Handler for all server requests. This will call the relevent function based 
 * on the parsed command code
 */
void* handle_server_request_thread(void *vargp)
{
    char buf[MAXLINE];
    compsys_helper_state_t state;

    int connfd = *((int *)vargp);
    pthread_detach(pthread_self()); 
    free(vargp);

    
    /*
    5: Reading Server Requests
    Here we should probably actually read in some input data.
    */
    char request_header[REQUEST_HEADER_LEN];
    char request_body[MAX_MSG_LEN];
    compsys_helper_readinitb(&state, connfd);
    compsys_helper_readnb(&state, request_header, REQUEST_HEADER_LEN);

    // reading header
    struct RequestHeader request;
    memcpy(&request, request_header, REQUEST_HEADER_LEN);

    char request_ip[IP_LEN + 1];
    memcpy(request_ip, request.ip, IP_LEN);
    request_ip[IP_LEN] = '\0';
    
    uint32_t request_port = ntohl(request.port);
    uint32_t request_command = ntohl(request.command);
    uint32_t request_length = ntohl(request.length);

    // for testing
    printf("ip=%s port=%u command=%u length=%u\n",
       request_ip, request_port, request_command, request_length);
    
    // step 9: handling inform message
    if (request_length > MAX_MSG_LEN - REQUEST_HEADER_LEN) {
        fprintf(stderr, "Request too long\n");
        close(connfd);
        return NULL;
    }
    if (request_length > 0) {
        compsys_helper_readnb(&state, request_body, request_length);
    }

    if (request_command == COMMAND_REGISTER) {
        handle_register(connfd, request_ip, request_port, (char*)request.signature);
    } else if (request_command == COMMAND_INFORM) {
        handle_inform(request_body, request_length);
    }

    close(connfd);

    return NULL;
}

/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void* server_thread()
{
    int listenfd;
    
    // Start listening
    char port_char[6];
    port_char[5] = '\0';
    sprintf(port_char, "%d", my_address->port);
    listenfd = compsys_helper_open_listenfd(port_char);
    
    printf("Starting to listen on %s:%d\n", my_address->ip, my_address->port);
    
    /*
    4: Setting Up Server Threading
    Here we should implement some sort of loop to accept inbound communications
    and handle them within a thread so they do not block subsequent 
    connections. The function 'handle_server_request_thread' has been provided
    as a simple skeleton function you could use to process your requests in.
    */
    int *connfd;
    struct sockaddr_in clientaddr;
    int lis_addr_len = sizeof(clientaddr);
    pthread_t tid;

    while(1) {
        // Accept incoming connections
        connfd = malloc(sizeof(int));
        *connfd = accept(listenfd, (struct sockaddr*)&clientaddr, (socklen_t*)&lis_addr_len);
        pthread_create(&tid, NULL, handle_server_request_thread, connfd);
    }

    // You should never see this printed in your finished implementation
    printf("Server thread done\n");

    return NULL;
}

int main(int argc, char **argv)
{
    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    my_address = (Address_t*)malloc(sizeof(Address_t));
    memset(my_address->ip, '\0', IP_LEN);
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip)) {
        fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
    }
    
    if (!is_valid_port(my_address->port)) {
        fprintf(stderr, ">> Invalid peer port: %d\n", 
            my_address->port);
        exit(EXIT_FAILURE);
    }

    char password[PASSWORD_LEN + 1]; // added + 1 for \0
    fprintf(stdout, "Create a password to proceed: ");
    scanf("%16s", password);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(password); i<PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }

    // Most correctly, we should randomly generate our salts, but this can make
    // repeated testing difficult so feel free to use the hard coded salt below
    char user_salt[SALT_LEN+1] = "0123456789ABCDEF\0";
    //generate_random_salt(user_salt);
    memcpy(my_address->salt, user_salt, SALT_LEN);

    /* 
    1: Setting Up
    After determining our salt but before saving our address we should probably
    work out what our signature should be. 
    */     
    hashdata_t* signature = (hashdata_t*)malloc(sizeof(hashdata_t));   
    get_signature(password, PASSWORD_LEN, my_address->salt, signature);
    memcpy(my_address->signature, signature, SHA256_HASH_SIZE);
    free(signature);

    // Start our record of the network by recording our own address. Make sure
    // any time we update this array we also update the peer_count.
    network = malloc(sizeof(Address_t*));
    network[0] = my_address;
    peer_count = 1;

    // Setup the client and server threads 
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Wait for them to complete. 
    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}