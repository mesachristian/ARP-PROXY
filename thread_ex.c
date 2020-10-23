#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct
{
    char *saludo;
    int edad; 
}DATA;

void *saludo(void *data){
    
    while (1)
    {
        printf("%s",(char *)data);
    }
}

int main(){
    pthread_t proc_1;
    pthread_t proc_2;

    pthread_create(&proc_1,NULL,&saludo,"hola\n");

    pthread_create(&proc_2,NULL,&saludo,"adios\n");
    
    pthread_join(proc_1,NULL);
    pthread_join(proc_2,NULL);

    return 0;
}