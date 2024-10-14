/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <aes_ta.h>

//#define AES_TEST_BUFFER_SIZE	512
#define AES_TEST_KEY_SIZE	16
#define AES_BLOCK_SIZE		16

#define DECODE			0
#define ENCODE			1

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};
/*
void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_AES_UUID;
	uint32_t origin;
	TEEC_Result res;

	// Initialize a context connecting us to the TEE 
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	// Open a session with the TA 
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}
*/
void opensession(struct test_ctx *ctx)
{

	TEEC_UUID uuid = TA_AES_UUID;
	uint32_t origin;

	TEEC_Result res;
	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
				res, origin);
}
void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

}
void closesession(struct test_ctx *ctx)
{

	TEEC_CloseSession(&ctx->sess);
}
void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_FinalizeContext(&ctx->ctx);
}

/*
void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}
*/
void prepare_aes(struct test_ctx *ctx, int encode)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);

	op.params[0].value.a = TA_AES_ALGO_CTR;
	op.params[1].value.a = TA_AES_SIZE_128BIT;
	op.params[2].value.a = encode ? TA_AES_MODE_ENCODE :
					TA_AES_MODE_DECODE;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_PREPARE,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
			res, origin);
}

void set_key(struct test_ctx *ctx, char *key, size_t key_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = key_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_KEY,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
			res, origin);
}

void set_iv(struct test_ctx *ctx, char *iv, size_t iv_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = iv_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_IV,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
			res, origin);
}


void cipher_buffer(struct test_ctx *ctx, char *in, char *out, size_t sz,int user,int infile,int index)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_OUTPUT,
			TEEC_VALUE_INPUT,
			TEEC_VALUE_INPUT);
	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = sz;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sz;
	op.params[2].value.a=infile;
	op.params[3].value.a=index;

	if(user>=1 && user <=2)
	{

		res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER_NEW,&op, &origin);

		if(res==PASSWORD_MATCH)
		{
			printf("\033[1;32m PASSWORD MATCH \n");
			return;
		}
		else if(res == PASSWORD_NOT_MATCH)
		{
			printf("\033[1;31m PASSWORD NOT MATCH \n");
			return;
		}
		if (res != TEEC_SUCCESS)
		{
			printf("Password Not Match Plese Re-try\n");
			errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x \n",res, origin);
		}
	}

	else
	{
		printf("\n call to exit\n");
		res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER_NEW_EXIT,&op, &origin);
		if (res != TEEC_SUCCESS)
		{
			printf("Password else Not Match Plese Re-try\n");
			errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x \n",res, origin);
		}

	}


}
int main()
{
	TEEC_Result res;
	struct test_ctx ctx;
	char key[AES_TEST_KEY_SIZE]={'d','i','g','a','m','b','a','r','j','o','n','d','h','a','l','e'};
	char iv[AES_BLOCK_SIZE];
	char clear[AES_TEST_BUFFER_SIZE];
	char ciph[AES_TEST_BUFFER_SIZE];
	int password,log;
	char buffer[20];
	char username[20];
	FILE *fd;
	static int c_index=0,inc_counter=0,temp;
	static int filein=0;
	int count=1;

	printf("Prepare session with the TA\n\n");
	prepare_tee_session(&ctx);


	while(1)
	{
		printf("\033[1;31m\nCreate Account Enter the 1 :-\nLogin Page Enter The 2 :-\n Exit from program Enter 3\n");
		scanf("%d",&log);

		if(log != 3)
		{

			printf("\033[1;33mEnter the username :- ");
			scanf(" %s",username);
			printf("\nEnter the password:- ");
			scanf(" %d",&password);
		}

		switch(log)
		{
			case 1:

				printf("\033[1;33m\nNew Password And Username Added\n");

				fd=fopen("username.txt","a+");
				fprintf(fd,"%s",username);
				fputc('\n',fd);
				fclose(fd);
				opensession(&ctx);

				//                      printf("Prepare encode operation\n");
				prepare_aes(&ctx, ENCODE);
				//                      printf("Load key in TA\n");
				set_key(&ctx, key, AES_TEST_KEY_SIZE);

				//                      printf("Load IV in ta)\n");
				memset(iv, 0, sizeof(iv)); /* Load some dummy value */
				set_iv(&ctx, iv, AES_BLOCK_SIZE);

				memset(clear, password, sizeof(clear)); /* Load some dummy value */

				filein=filein & ~(1<<1);// logic for file creating one time 1st bit is clear 
				temp=inc_counter;// counter for increment the ta pointer data writing 

				cipher_buffer(&ctx, clear, ciph, AES_TEST_BUFFER_SIZE,log,filein,temp);
				filein=filein | (1<<0);// logic for file creating one time zero(0)th  bit is set 
				inc_counter++;
				printf("\033[1;32m\nThanks .... !!!!!!!\n");
				closesession(&ctx);
				break;
			case 2:
				if(inc_counter==0)
				{
					printf("\033[1;31m\nNo Data Found Plese Enter The Data For Login\n");
					break;
				}
				opensession(&ctx);
				fd=fopen("username.txt","r+");
				rewind(fd);
				int r=0;
				while(fscanf(fd,"%s",buffer)!=EOF)
				{
					r=strcmp(username,buffer);
					if(r==0)
						break;
					count++;


				}
				if(r==0)
				{

					printf("\033[1;32mFind Username cheak the password\n");
					filein=filein | (1<<1);// read 1st bit is set that means is login page for ta 

					//printf("Prepare encode operation\n");
					prepare_aes(&ctx, ENCODE);
					//printf("Load key in TA\n");
					set_key(&ctx, key, AES_TEST_KEY_SIZE);

					//printf("Load IV in TA\n");
					memset(iv, 0, sizeof(iv)); /* Load some dummy value */
					set_iv(&ctx, iv, AES_BLOCK_SIZE);

					memset(clear, password, sizeof(clear)); /* Load some dummy value */

					temp=count;// counter is use for where data read in ta save data write time 
					cipher_buffer(&ctx, clear, ciph, AES_TEST_BUFFER_SIZE,log,filein,temp);

					count=1;//user after next reading time counter use 

					printf("\033[1;32m\nThanks .... !!!!!!!\n");
				}

				else
				{
					printf("\033[1;31mUser Name Not Found Plese Login \n");
					printf("\033[1;31m\nThanks .... !!!!!!!\n");
					count=1;
					break;
				}
				fclose(fd);

				closesession(&ctx);
				break;
			case 3:
				opensession(&ctx);
				prepare_aes(&ctx, ENCODE);
				filein=0;
				count=1;
				fd=fopen("username.txt","w");
				fclose(fd);

				set_key(&ctx, key, AES_TEST_KEY_SIZE);

				//printf("Load IV in TA\n");
				memset(iv, 0, sizeof(iv)); /* Load some dummy value */
				set_iv(&ctx, iv, AES_BLOCK_SIZE);

				memset(clear, password, sizeof(clear)); /* Load some dummy value */

				cipher_buffer(&ctx, clear, ciph, AES_TEST_BUFFER_SIZE,log,filein,temp);
				closesession(&ctx);
				terminate_tee_session(&ctx);
				return 0;
		}



	}
	printf("Password Is Match Run Appliction\n");


	terminate_tee_session(&ctx);


	return 0;
}




/*
void cipher_buffer(struct test_ctx *ctx, char *in, char *out, size_t sz,int user,int infile,int index)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
			TEEC_MEMREF_TEMP_OUTPUT,
			TEEC_VALUE_INPUT,
			TEEC_VALUE_INPUT);
	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = sz;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sz;
	op.params[2].value.a=infile;
	op.params[3].value.a=index;


	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER_NEW,&op, &origin);

	if(res==PASSWORD_MATCH)
	{
		printf("\033[1;32m PASSWORD MATCH \n");
		return;
	}
	else if(res == PASSWORD_NOT_MATCH)
	{
		printf("\033[1;31m PASSWORD NOT MATCH \n");
		return;
	}
	if (res != TEEC_SUCCESS)
	{
		printf("Password Not Match Plese Re-try\n");
		errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x \n",res, origin);
	}

}

int main()
{
	TEEC_Result res;
	struct test_ctx ctx;
	char key[AES_TEST_KEY_SIZE]={'d','i','g','a','m','b','a','r','j','o','n','d','h','a','l','e'};
	char iv[AES_BLOCK_SIZE];
	char clear[AES_TEST_BUFFER_SIZE];
	char ciph[AES_TEST_BUFFER_SIZE];
	int password,log;
	char buffer[20];
	char username[20];
	FILE *fd;
	static int c_index=0,inc_counter=0,temp;
	static int filein=0;
	int count=1;

	printf("Prepare session with the TA\n\n");
	prepare_tee_session(&ctx);


	while(1)
	{
		printf("\033[1;31m\nCreate Account Enter the 1 :-\nLogin Page Enter The 2 :-\n");
		scanf("%d",&log);

		printf("\033[1;33mEnter the username :- ");
		scanf(" %s",username);
		printf("\nEnter the password:- ");
		scanf(" %d",&password);

		switch(log)
		{
			case 1:

				printf("\033[1;33m\nNew Password And Username Added\n");

				fd=fopen("username.txt","a+");
				fprintf(fd,"%s",username);
				fputc('\n',fd);
				fclose(fd);
				opensession(&ctx);

				//			printf("Prepare encode operation\n");
				prepare_aes(&ctx, ENCODE);
				//			printf("Load key in TA\n");
				set_key(&ctx, key, AES_TEST_KEY_SIZE);

				//			printf("Load IV in ta)\n");
				memset(iv, 0, sizeof(iv)); // Load some dummy value 
				set_iv(&ctx, iv, AES_BLOCK_SIZE);

				memset(clear, password, sizeof(clear)); // Load some dummy value /

				filein=filein & ~(1<<1);// logic for file creating one time 1st bit is clear 
				temp=inc_counter;// counter for increment the ta pointer data writing 

				cipher_buffer(&ctx, clear, ciph, AES_TEST_BUFFER_SIZE,log,filein,temp);
				filein=filein | (1<<0);// logic for file creating one time zero(0)th  bit is set 
				inc_counter++;
				printf("\033[1;32m\nThanks .... !!!!!!!\n");	
				closesession(&ctx);
				break;
			case 2:
				if(inc_counter==0)
				{
					printf("\033[1;31m\nNo Data Found Plese Enter The Data For Login\n");
					break;
				}
				opensession(&ctx);
				fd=fopen("username.txt","r+");
				rewind(fd);
				int r=0;
				while(fscanf(fd,"%s",buffer)!=EOF)
				{
					r=strcmp(username,buffer);
					if(r==0)
						break;
					count++;


				}
				if(r==0)
				{

					printf("\033[1;32mFind Username cheak the password\n");
					filein=filein | (1<<1);// read 1st bit is set that means is login page for ta 

					//printf("Prepare encode operation\n");
					prepare_aes(&ctx, ENCODE);
					//printf("Load key in TA\n");
					set_key(&ctx, key, AES_TEST_KEY_SIZE);

					//printf("Load IV in TA\n");
					memset(iv, 0, sizeof(iv)); // Load some dummy value /
					set_iv(&ctx, iv, AES_BLOCK_SIZE);

					memset(clear, password, sizeof(clear)); // Load some dummy value /

					temp=count;// counter is use for where data read in ta save data write time 
					cipher_buffer(&ctx, clear, ciph, AES_TEST_BUFFER_SIZE,log,filein,temp);

					count=1;//user after next reading time counter use 

					printf("\033[1;32m\nThanks .... !!!!!!!\n");	
				}
				else
				{
					printf("\033[1;31mUser Name Not Found Plese Login \n");
					printf("\033[1;31m\nThanks .... !!!!!!!\n");	
					break;
				}
				fclose(fd);

				closesession(&ctx);
				break;
		}


	}
	printf("Password Is Match Run Appliction\n");


	terminate_tee_session(&ctx);


	return 0;
}
*/









/*
   void cipher_buffer(struct test_ctx *ctx, char *in, char *out, size_t sz)
   {
   TEEC_Operation op;
   uint32_t origin;
   TEEC_Result res;

   memset(&op, 0, sizeof(op));
   op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
   TEEC_MEMREF_TEMP_OUTPUT,
   TEEC_NONE, TEEC_NONE);
   op.params[0].tmpref.buffer = in;
   op.params[0].tmpref.size = sz;
   op.params[1].tmpref.buffer = out;
   op.params[1].tmpref.size = sz;

   res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER,
   &op, &origin);
   if (res != TEEC_SUCCESS)
   {
   printf("PASSWORD NOT MATCH IN NORMAL WORLD\n");

   errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
   res, origin);
   }
   else
   {
   printf("PASSWORD IS MATCH IN NORMAL WORLD\n");
   }
   }

   int main(void)
   {

   struct test_ctx ctx;
   char key[AES_TEST_KEY_SIZE]={'d','i','g','a','m','b','a','r','j','o','n','d','h','a','l','e'};
   char iv[AES_BLOCK_SIZE];
   char clear[AES_TEST_BUFFER_SIZE];
   char ciph[AES_TEST_BUFFER_SIZE];
   char temp[AES_TEST_BUFFER_SIZE];
   char buffer[30];
   int password;


   printf("Enter the user name\n");
   scanf("%s",buffer);

   printf("Enter the password\n");
   scanf("%d",&password);
   printf("Prepare session with the TA\n");
   prepare_tee_session(&ctx);

   printf("Prepare encode operation\n");
   prepare_aes(&ctx, ENCODE);

   printf("Load key in TA\n");
   set_key(&ctx, key, AES_TEST_KEY_SIZE);

   printf("Reset ciphering operation in TA (provides the initial vector)\n");
   memset(iv, 0, sizeof(iv)); // Load some dummy value 
   set_iv(&ctx, iv, AES_BLOCK_SIZE);

   printf("Encode buffer from TA\n");
   memset(clear, password, sizeof(clear)); // Load some dummy value 
   cipher_buffer(&ctx, clear, ciph, AES_TEST_BUFFER_SIZE);

   terminate_tee_session(&ctx);
   return 0;
   }*/


