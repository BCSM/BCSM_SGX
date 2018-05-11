// Copyright (C) 2017-2018 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "sgx_tseal.h"
#include "app.h"
#include "Enclave_u.h"


sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;

    if (home_dir != NULL &&
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }
    printf("[+] global_eid: %ld\n", global_eid);

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_status_t enclave_ret = SGX_SUCCESS;
    uint32_t sealed_log_size = 1024;
    uint8_t sealed_log[1024] = {0};
    int i;

    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    printf("[+] doctor_ecc_keygen started!\n");
    uint8_t ecc_pk_gx[32] = {0};
    uint8_t ecc_pk_gy[32] = {0};
    //uint8_t ecc_sk[32] = {0};
    sgx_sealed_data_t * sealed_data = 0;

    printf("[+] doctor_ecc_keygen args prepared!\n");
    sgx_ret = doctor_ecc_keygen(global_eid,
                                &enclave_ret,
                                ecc_pk_gx,
                                ecc_pk_gy,
                                sealed_log,
                                sealed_log_size);
    printf("[+] sealling log returned from enclave!\n");
    if(sgx_ret != SGX_SUCCESS) {
      print_error_message(sgx_ret);
      return -1;
    }
    if(enclave_ret != SGX_SUCCESS) {
      print_error_message(enclave_ret);
      return -1;
    }

    printf("[+] doctor's public key is:\n");
    fprintf(stderr, "doctor_PK ");
    for(i = 0; i < 32; i ++) {
        printf("%02x", ecc_pk_gx[i]);
        fprintf(stderr, "%02x", ecc_pk_gx[i]);
    }
    printf("\n");
    fprintf(stderr, " ");
    for(i = 0; i < 32; i ++) {
        printf("%02x", ecc_pk_gy[i]);
        fprintf(stderr, "%02x", ecc_pk_gy[i]);
    }
    printf("\n");
    fprintf(stderr, "\n");

    printf("[+] create_sealeddata success ...\n");
    sealed_data = (sgx_sealed_data_t *)sealed_log;
    printf("[+] sealed_data.key_request.key_name 0x%x\n", sealed_data->key_request.key_name);
    printf("[+] sealed_data.key_request.key_policy 0x%x\n", sealed_data->key_request.key_policy);
    printf("[+] sealed_data.plain_text_offset 0x%x\n", sealed_data->plain_text_offset);
    printf("[+] sealed_data.aes_data.payload_size 0x%x\n", sealed_data->aes_data.payload_size);

    printf("[=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=]\n");
    printf("[+] doctor_generate_rx started!\n");
    uint8_t plaintext[16] = {'c', 'w', 'k', '|', '|', 'c', 'v', 's'};
    uint8_t patientID[16] = {'c', 'w', 'k', '1', '9', '9', '4'};
    uint8_t patientInfo_aes_gcm_iv[12] = {0};
    uint8_t patientInfo_aes_gcm_ciphertext[16] = {0};
    uint8_t patientInfo_aes_gcm_mac[16] = {0};

    uint32_t sig_x[8] = {0};
    uint32_t sig_y[8] = {0};

    uint8_t ecc_pub_gx[32] = {0};
    uint8_t ecc_pub_gy[32] = {0};

    uint8_t ecc_cipher[16] = {0};

    uint8_t key_aes_gcm_iv[12] = {0};
    uint8_t key_aes_gcm_ciphertext[16] = {0};
    uint8_t key_aes_gcm_mac[16] = {0};

    printf("[+] doctor_generate_rx args prepared!\n");
    sgx_ret = doctor_generate_rx(global_eid,
                                 &enclave_ret,
                                 patientID,
                                 plaintext,
                                 16,
                                 patientInfo_aes_gcm_iv,
                                 patientInfo_aes_gcm_ciphertext,
                                 patientInfo_aes_gcm_mac,
                                 ecc_pk_gx,
                                 ecc_pk_gy,
                                 sealed_log,
                                 sealed_log_size,
                                 sig_x,
                                 sig_y,
                                 ecc_pub_gx,
                                 ecc_pub_gy,
                                 ecc_cipher,
                                 key_aes_gcm_iv,
                                 key_aes_gcm_ciphertext,
                                 key_aes_gcm_mac
                                 );
    printf("[+] rx returned from enclave!\n");

    //printf("%02x\n", aes_gcm_iv[1]);

    if(sgx_ret != SGX_SUCCESS) {
        print_error_message(sgx_ret);
        return -1;
    }

    if(enclave_ret != SGX_SUCCESS) {
        print_error_message(enclave_ret);
        return -1;
    }

    printf("[+] rx's iv for patientInfo is: ");
    fprintf(stderr, "patientInfo_iv ");
    for(i = 0; i < 12; i ++) {
        printf("%02x", patientInfo_aes_gcm_iv[i]);
        fprintf(stderr, "%02x", patientInfo_aes_gcm_iv[i]);
    }
    printf("\n");
    fprintf(stderr, "\n");

    printf("[+] rx's ciphertext for patientInfo is: ");
    fprintf(stderr, "patientInfo_cipher ");
    for(i = 0; i < 16; i ++) {
        printf("%02x", patientInfo_aes_gcm_ciphertext[i]);
        fprintf(stderr, "%02x", patientInfo_aes_gcm_ciphertext[i]);
    }
    printf("\n");
    fprintf(stderr, "\n");

    printf("[+] rx's mac for patientInfo is: ");
    fprintf(stderr, "patientInfo_mac ");
    for(i = 0; i < 16; i ++) {
        printf("%02x", patientInfo_aes_gcm_mac[i]);
        fprintf(stderr, "%02x", patientInfo_aes_gcm_mac[i]);
    }
    printf("\n");
    fprintf(stderr, "\n");

    printf("[+] temporary public key for ecc encryption is: \n");
    fprintf(stderr, "tmp_pk ");
    for(i = 0; i < 32; i ++) {
        printf("%02x", ecc_pub_gx[i]);
        fprintf(stderr, "%02x", ecc_pub_gx[i]);
    }
    printf("\n");
    fprintf(stderr, " ");
    for(i = 0; i < 32; i ++) {
        printf("%02x", ecc_pub_gy[i]);
        fprintf(stderr, "%02x", ecc_pub_gy[i]);
    }
    printf("\n");
    fprintf(stderr, "\n");

    printf("[+] ecc_cipher for temporary aes key is: ");
    fprintf(stderr, "ecc_ciphertext ");
    for(i = 0; i < 16; i ++) {
        printf("%02x", ecc_cipher[i]);
        fprintf(stderr, "%02x", ecc_cipher[i]);
    }
    printf("\n");
    fprintf(stderr, "\n");

    printf("[+] rx's iv for patientID is: ");
    fprintf(stderr, "patientID_iv ");
    for(i = 0; i < 12; i ++) {
        printf("%02x", key_aes_gcm_iv[i]);
        fprintf(stderr, "%02x", key_aes_gcm_iv[i]);
    }
    printf("\n");
    fprintf(stderr, "\n");

    printf("[+] rx's ciphertext for patientID is: ");
    fprintf(stderr, "patientID_ciphertext ");
    for(i = 0; i < 16; i ++) {
        printf("%02x", key_aes_gcm_ciphertext[i]);
        fprintf(stderr, "%02x", key_aes_gcm_ciphertext[i]);
    }
    printf("\n");
    fprintf(stderr, "\n");

    printf("[+] rx's mac for patientID is ");
    fprintf(stderr, "patientID_mac ");
    for(i = 0; i < 16; i ++) {
        printf("%02x", key_aes_gcm_mac[i]);
        fprintf(stderr, "%02x", key_aes_gcm_mac[i]);
    }
    printf("\n");
    fprintf(stderr, "\n");

    printf("[+] rx's signature is \n");
    fprintf(stderr, "record_sig ");
    for(i = 0; i < 8; i ++) {
        printf("%08x", sig_x[i]);
        fprintf(stderr, "%08x", sig_x[i]);
    }
    printf("\n");
    fprintf(stderr, " ");
    for(i = 0; i < 8; i ++) {
        printf("%08x", sig_y[i]);
        fprintf(stderr, "%08x", sig_y[i]);
    }
    printf("\n");
    fprintf(stderr, "\n");

    printf("[+] doctor_generate_rx decrypt complete \n");

    printf("[=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=]\n");
    printf("[+] Starting pharmacy_decode_rx decrypt calculation\n");
    uint8_t pharmacy_aes_gcm_decrypted_text[16] = {0};
    sgx_ret = pharmacy_decode_rx(global_eid,
                                  &enclave_ret,
                                  patientID,
                                  patientInfo_aes_gcm_ciphertext,
                                  16,
                                  patientInfo_aes_gcm_iv,
                                  patientInfo_aes_gcm_mac,
                                  pharmacy_aes_gcm_decrypted_text,
                                  ecc_pk_gx,
                                  ecc_pk_gy,
                                  sig_x,
                                  sig_y,
                                  ecc_pub_gx,
                                  ecc_pub_gy,
                                  ecc_cipher,
                                  key_aes_gcm_iv,
                                  key_aes_gcm_ciphertext,
                                  key_aes_gcm_mac
                                  );

    if(sgx_ret != SGX_SUCCESS) {
        print_error_message(sgx_ret);
        return -1;
    }
    if(enclave_ret != SGX_SUCCESS) {
        print_error_message(enclave_ret);
        return -1;
    }

    printf("[+] rx plaintext is: ");
    for(i = 0; i < 16; i ++) {
        printf("%c", pharmacy_aes_gcm_decrypted_text[i]);
    }
    printf("\n");
    printf("[+] pharmacy_decode_rx decrypt and verify signature complete \n");

    printf("[=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=] [=]\n");
    printf("[+] Starting government_decode_rx decrypt calculation\n");
    uint8_t gov_sk[32] = {0xde, 0x8c, 0xab, 0xf7,
                          0x7b, 0x11, 0x6e, 0x06,
                          0x31, 0x02, 0xb6, 0xee,
                          0x30, 0xa9, 0xfd, 0xc4,
                          0x37, 0xd4, 0xcf, 0x01,
                          0x37, 0x8b, 0x5d, 0xe1,
                          0xfc, 0x0a, 0x5a, 0x99,
                          0x54, 0xa9, 0xe3, 0x93};
    uint8_t government_aes_gcm_decrypted_text[16] = {0};

    sgx_ret = government_decode_rx(global_eid,
                                  &enclave_ret,
                                  gov_sk,
                                  patientInfo_aes_gcm_ciphertext,
                                  16,
                                  patientInfo_aes_gcm_iv,
                                  patientInfo_aes_gcm_mac,
                                  government_aes_gcm_decrypted_text,
                                  ecc_pk_gx,
                                  ecc_pk_gy,
                                  sig_x,
                                  sig_y,
                                  ecc_pub_gx,
                                  ecc_pub_gy,
                                  ecc_cipher,
                                  key_aes_gcm_iv,
                                  key_aes_gcm_ciphertext,
                                  key_aes_gcm_mac
                                  );

    if(sgx_ret != SGX_SUCCESS) {
        print_error_message(sgx_ret);
        return -1;
    }
    if(enclave_ret != SGX_SUCCESS) {
        print_error_message(enclave_ret);
        return -1;
    }

    printf("[+] rx plaintext is: ");
    for(i = 0; i < 16; i ++) {
        printf("%c", pharmacy_aes_gcm_decrypted_text[i]);
    }
    printf("\n");
    printf("[+] government_decode_rx decrypt and verify signature complete \n");

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    return 0;
}
