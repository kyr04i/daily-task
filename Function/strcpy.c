#include <stdio.h> 
#include <unistd.h>

char *Strcpy(char *dest, const char *src) 
{
    char *d = dest; 

    while (*src != '\0') {      
        *d = *src;           
        d++;                 
        src++;                 
    }
    *d = '\0';              
    return dest;
}

int main()
{
    char a[100], b[100];
    read(0, a, 20);
    Strcpy(b, a);
    printf("%s", b);
}