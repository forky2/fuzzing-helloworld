/*
Author: Hardik Shah
Email: hardik05@gmail.com
Web: http://hardik05.wordpress.com

Modified by: https://github.com/electricworry
*/

// A vulnerable c program to explain common vulnerability types

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

struct Image
{
	char header[4];
	int width;
	int height;
	char data[10];
};

void stack_operation(void)
{
	char buff[0x1000];
	while(1)
	{
		stack_operation();
	}
}

int slow_init(void)
{
	int i = 0;
	while (i < 1000000)
	{
		printf("Hello\n");
		i++;
	}
}

int process_image(struct Image *img)
{
	if(strcmp(img->header,"IMG") == 0)
	{
		printf("Header\twidth\theight\tdata\n");
		printf("%s\t%d\t%d\t%s\n",img->header,img->width,img->height,img->data);

		//integer overflow 0x7FFFFFFF+1=0
		//0x7FFFFFFF+2 = 1
		//will cause very large/small memory allocation.
		int size1 = img->width + img->height;
		char* buff1 = (char*) malloc(size1);

		//heap buffer overflow
		memcpy(buff1, img->data, sizeof(img->data));
		free(buff1);

		if (size1 % 10 == 7)
		{
			printf("Double free!\n");
			free(buff1);
		}
		else if (size1 % 10 == 8)
		{
			printf("Use after free!\n");
			buff1[0]='a';
		}

		//integer underflow 0-1=-1
		//negative so will cause very large memory allocation
		int size2 = img->width - img->height + 100;
		char* buff2 = (char*) malloc(size2);

		//heap buffer overflow
		memcpy(buff2, img->data, sizeof(img->data));

		//divide by zero
		int size3 = img->width / img->height;

		char buff3[sizeof(struct Image)];
		char* buff4 = (char*) malloc(size3 + 1);
		memcpy(buff4, img->data, sizeof(img->data));

		//OOBR read bytes past stack/heap buffer
		char oobr = buff3[size3];
		char oobr_heap = buff4[img->height];

		//OOBW write bytes past stack/heap buffer
		buff3[size3]='c';
		buff4[size3]='c';

		if(size3 % 11 == 0)
		{
			printf("Memory leak!\n");
			buff4 = NULL;
		}
		else
		{
			free(buff4);
		}

		int size4 = img->width * img->height;
		if(size4 % 100 == 43)
		{
			// stack exhaustion here
			stack_operation();
		}
		else if (size4 % 100 == 72)
		{
			// heap exhaustion here
			char *buff5;
			do
			{
				buff5 = (char*) malloc(size4);
			} while(buff5);
		}
		free(buff2);
	}
	else
	{
		printf("Invalid header\n");
	}
	
	return 0;
}

int main(int argc,char **argv)
{
	printf("HELLO\n");
	FILE *fp;
	struct Image img;
	
	slow_init();

	if (argc < 2)
	{
		// Read from STDIN
		fp = stdin;
	}
	else
	{
		fp = fopen(argv[1], "r");
	}
	fread(&img, 1, sizeof(img), fp);
	fclose(fp);
	process_image(&img);

	return 0;
}
