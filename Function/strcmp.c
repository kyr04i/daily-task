#include <stdio.h> 
#include <unistd.h>

int Strcmp(const char *p1, const char *p2) 
{
    const unsigned char *s1 = (const unsigned char *) p1;
    const unsigned char *s2 = (const unsigned char *) p2;
    unsigned char c1, c2;

    c1 = (unsigned char) *s1;
    c2 = (unsigned char) *s2;

    while(c1 == c2)
    {
        if(c1 == '\0') return c1 - c2;
        c1 = (unsigned char) *s1++;
        c2 = (unsigned char) *s2++;
    }
    return c1 - c2;
}

int main()
{
    const char *a = "abc xyz";
    const char *b = "abc xyz";
    int res = Strcmp(a, b);
    printf("%d", res);
}