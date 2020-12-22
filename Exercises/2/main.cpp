#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
//#include "ThemidaSDK.h"

char buf[1204];

bool mystrcmp(char *p1, char*p2){
	//VM_EAGLE_BLACK_START
	while (*p1 & *p2)
	{
		if (*p1 != *p2)
			return false;
		p1++;
		p2++;
	}
	if (*p1 || *p2)
		return false;
	return true;
	//VM_EAGLE_BLACK_END

}

void main()
{
	//VM_EAGLE_BLACK_START
	while (1)
	{
		scanf("%s", buf);
		if(mystrcmp(buf, "123"))
			printf("ok\n");
		else
			printf("fail\n");
	}
	system("pause");
	//VM_EAGLE_BLACK_END
}
