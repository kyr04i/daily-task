#include <stdio.h> 
#include <unistd.h>

int Memcmp(const char *p1, const char *p2, size_t len) 
{
    const unsigned char *s1 = (const unsigned char*)p1;
    const unsigned char *s2 = (const unsigned char*)p2;

    while (len > 0 && *s1 == *s2)
    {
        s1++;
        s2++;
        len--;
    }
    if(len == 0) return 0;
    else return *s1 - *s2;
}

int main()
{
    const char *a = "abc xyz";
    const char *b = "abc Xyz";
    int res = Memcmp(a, b, 10);
    printf("%d", res);
}