#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

void *Memcpy (void *dest, const void *src, size_t len)
{
	unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    for(int i = 0; i < len; i++)
    	d[i] = s[i];

    return dest;	
}

int main() 
{
	char buf[100];
	read(0, buf, sizeof(buf));
	char s[100];
	Memcpy(s, buf, sizeof(buf));
	printf("%s", s);
}
