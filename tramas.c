/***
 * Para compilar:
 * 1. Obtener el .o: gcc -c tramas.c -o tramas.o
 * 2. Crear el .lib: ar rcs tramas.lib tramas.o
*/
#include "tramas.h"
#include <stdio.h>
#include <stdlib.h>

/************************************************ FUNCIONES ETHERNET ************************************************/
void crearTramaEthernet(TRAMA_ETHERNET *trama, BYTE_T *datos){
    int i,j;
    for(i=0; i < 6; i++){ // Dirección de destino
        *((trama->dir_destino) + i) = *(datos + i);
    }

    for(i=6,j=0; i < 12; j++,i++){ // Dirección de origen
        *((trama->dir_origen) + j) = *(datos + i);
    }

    for(i=12,j=0; i < 14; j++,i++){
        *((trama->tipo_lon) + j) = *(datos + i);
    }
    trama->datos = (datos + i);
}

void imprimirTramaEthernet(TRAMA_ETHERNET trama, int longitudTrama){
    int i,j;
    printf("DIRECCION DESTINO: ");
    for(i=0; i < 6; i++){
        printf("%x  ",trama.dir_destino[i]);
    }
    printf("\nDIRECCION ORIGEN: ");
    for(i=0; i < 6; i++){
        printf("%x  ",trama.dir_origen[i]);
    }
    printf("\nDIRECCION TIPO/LONGITUD: ");
    for(i=0; i < 2; i++){
        printf("%x  ",trama.tipo_lon[i]);
    }

    printf("\nDATOS: ");
    for(i=14,j=0; i < longitudTrama; j++,i++){
        printf("%x  ",*(trama.datos + j));
    }
    printf("\n");
}

/************************************************** FUNCIONES ARP ***************************************************/
void crearTramaARP(TRAMA_ARP *trama, BYTE_T *datos){
    int i,j;
    for(i=0; i < 2; i++){ // Tipo de hardware
        *((trama->tipoHardware) + i) = *(datos + i);
    }

    for(j=0; i < 4; j++,i++){ // Tipo de protocolo
        *((trama->tipoProtocolo) + j) = *(datos + i);
    }

    trama->longitudHardware = *(datos + i);
    i++;
    trama->longitudProtocolo = *(datos + i);
    i++;

    for(j=0; i < 8; j++,i++){ // Codigo de operación
        *((trama->opcode) + j) = *(datos + i);
    }

    trama->dirHardwareOrigen = (datos + i);
    i+= trama->longitudHardware;

    trama->dirProtocoloOrigen = (datos+i);
    i+= trama->longitudProtocolo;

    trama->dirHardwareDestino = (datos + i);
    i += trama->longitudHardware;

    trama->dirProtocoloDestino = (datos + i);
}

void imprimirTramaARP(TRAMA_ARP *trama){
    int i;
    printf("\nTIPO HARDWARE: ");
    for(i=0; i < 2; i++){
        printf("%x  ", *((trama->tipoHardware)+i));
    }

    printf("\nTIPO PROTOCOLO: ");
    for(i=0; i < 2; i++){
        printf("%x  ", *((trama->tipoProtocolo)+i));
    }

    printf("\nLONGITUD HARDWARE: %x",trama->longitudHardware);
    printf("\nLONGITUD PROTOCOLO: %x",trama->longitudProtocolo);

    printf("\nOPCODE: ");
    for(i=0; i < 2; i++){
        printf("%x  ", *((trama->opcode)+i));
    }

    printf("\nDIR HARDWARE ORIGEN: ");
    for(i=0; i < trama->longitudHardware; i++){
        printf("%x  ", *((trama->dirHardwareOrigen)+i));
    }

    printf("\nDIR PROTOCOLO ORIGEN: ");
    for(i=0; i < trama->longitudProtocolo; i++){
        printf("%d.", *((trama->dirProtocoloOrigen)+i));
    }

    printf("\nDIR HARDWARE DESTINO: ");
    for(i=0; i < trama->longitudHardware; i++){
        printf("%x  ", *((trama->dirHardwareDestino)+i));
    }

    printf("\nDIR PROTOCOLO DESTINO: ");
    for(i=0; i < trama->longitudProtocolo; i++){
        printf("%d.", *((trama->dirProtocoloDestino)+i));
    }
    printf("\n");
}

void armarPaqueteReplyARP(BYTE_T *dirMACDestino, BYTE_T *dirMACOrigen, BYTE_T *dirIPDestino, BYTE_T *dirIPOrigen, BYTE_T *paquete){
    
    BYTE_T packet[TAM_TRAMA_ARP];
    int i,j;
    
    for(i=0; i < 6; i++){ // Primero la dirección destino de capa 2
        packet[i] = *(dirMACDestino + i);
    }

    for(j=0; i < 12; j++,i++){ // Dirección de capa 2 del origen
        packet[i] = *(dirMACOrigen + j);
    }

    // TIPO: ARP
    packet[i++] = 8;
    packet[i++] = 6;

    // TIPO DE HARDWARE: Ethernet jama
    packet[i++] = 0;
    packet[i++] = 1;

    // TIPO DE PROTOCOLO :IPv4
    packet[i++] = 8;
    packet[i++] = 0;

    packet[i++] = 6; // Longitud de una MAC
    packet[i++] = 4; // Longitud de IPv4

    // OPCODE: 02 REPLY
    packet[i++] = 0;
    packet[i++] = 2;

    for(j=0; j < 6; j++,i++){ // Dirección MAC Origen
        packet[i] = *(dirMACOrigen + j);
    }

    for(j=0; j < 4; j++,i++){ // Dirección IP Origen
        packet[i] = *(dirIPOrigen + j);
    }

    for(j=0; j < 6; j++,i++){ // Dirección MAC Destino
        packet[i] = *(dirMACDestino + j);
    }

    for(j=0; j < 4; j++,i++){ // Dirección IP Destino
        packet[i] = *(dirIPDestino + j);
    }

    for(i=0;i < TAM_TRAMA_ARP; i++) // Pasar los datos
        *(paquete + i) = packet[i];
    
    for(i=42; i < 60; i++){ // Rellenar con ceros para cumplir el tamaño minimo de la trama
        *(paquete + i) = 0;
    }
}

/************************************************** FUNCIONES IP ***************************************************/
void crearTramaIPV4(TRAMA_IPV4 *trama, BYTE_T *datos){
    int i=1,j;
    trama->version_tamEncabezado = *(datos);
    trama->serviciosDiferenciados = *(datos + i);
    i++;
    for(j=0;j<2;j++,i++)
        *(trama->tamTotal + j) = *(datos + i);
    
    for(j=0;j<2;j++,i++)
        *(trama->identificacion + j) = *(datos + i);

    for(j=0;j<2;j++,i++)
        *(trama->banderas_offset + j) = *(datos + i);

    trama->tiempoDeVida = *(datos + i);
    i++;
    trama->protocolo = *(datos + i);
    i++;
    for(j=0;j<2;j++,i++)
        *(trama->checkSumEncabezado + j) = *(datos + i);

    for(j=0;j<4;j++,i++)
        *(trama->ipOrigen + j) = *(datos + i);
    
    for(j=0;j<4;j++,i++)
        *(trama->ipDestino + j) = *(datos + i);

    trama->datos = (datos + i);
}
void imprimirTramaIPV4(TRAMA_IPV4 *trama){
    int i;
    printf("VERSION y TAM_ENCABEZADO: %x\n",trama->version_tamEncabezado);
    printf("SERVICIOS DIFERENCIADOS: %x\n",trama->serviciosDiferenciados);
    printf("TAM TOTAL: ");
    for(i = 0; i < 2; i++)
        printf("%x  ",trama->tamTotal[i]);

    printf("\nIDENTIFICACION: ");
    for(i = 0; i < 2; i++)
        printf("%x  ",trama->identificacion[i]);

    printf("\nBANDERAS OFFSET: ");
    for(i = 0; i < 2; i++)
        printf("%x  ",trama->banderas_offset[i]);
    
    printf("\nTIEMPO DE VIDA: %x\n",trama->tiempoDeVida);
    printf("PROTOCOLO: %x\n",trama->protocolo);

    printf("CHECKSUM ENCABEZADO: ");
    for(i = 0; i < 2; i++)
        printf("%x  ",trama->checkSumEncabezado[i]);

    printf("\nIP ORIGEN: ");
    for(i = 0; i < 4; i++)
        printf("%d.",trama->ipOrigen[i]);

    printf("\nIP DESTINO: ");
    for(i = 0; i < 4; i++)
        printf("%d.",trama->ipDestino[i]);

    printf("\nDATOS: ");
    unsigned int t_datos = trama->tamTotal[1];
    t_datos |= (unsigned int)(trama->tamTotal[0] << 8);
    //printf("total:%d,%x",t_datos,t_datos);
    for(i=0; i < t_datos - 20; i++)
        printf("%x  ",*(trama->datos + i));

    printf("\n");
}

void armarPaqueteIP(BYTE_T *macOrigen,BYTE_T *macDestino,TRAMA_IPV4 tramaIP, BYTE_T *paquete){
    // meter encabezado eth0
    int i,j;
    for(i=0; i < 6; i++){ // Primero la dirección destino de capa 2
        *(paquete + i) = *(macDestino + i);
    }

    for(j=0; i < 12; j++,i++){ // Dirección de capa 2 del origen
        *(paquete + i) = *(macOrigen + j);
    }

    // TIPO: IPV4
    *(paquete + i) = 8;
    i++;
    *(paquete + i) = 0;
    i++;

    *(paquete + i) = tramaIP.version_tamEncabezado;
    i++;
    *(paquete + i) = tramaIP.serviciosDiferenciados;
    i++;

    for(j = 0; j < 2; j++,i++)
        *(paquete + i) = tramaIP.tamTotal[j];

    for(j = 0; j < 2; j++,i++)
        *(paquete + i) = tramaIP.identificacion[j];

    for(j = 0; j < 2; j++,i++)
        *(paquete + i) = tramaIP.banderas_offset[j];
    
    *(paquete + i) = tramaIP.tiempoDeVida;
    i++;
    *(paquete + i) = tramaIP.protocolo;
    i++;
    
    for(j = 0; j < 2; j++,i++)
        *(paquete + i) = tramaIP.checkSumEncabezado[j];

    for(j = 0; j < 4; j++,i++)
        *(paquete + i) = tramaIP.ipOrigen[j];

    for(j = 0; j < 4; j++,i++)
        *(paquete + i) = tramaIP.ipDestino[j];

    unsigned int t_datos = tramaIP.tamTotal[1];
    t_datos |= (unsigned int)(tramaIP.tamTotal[0] << 8);

    for(j = 0; j < t_datos - 20; j++,i++) // Se quitan los 20 de encabezado
        *(paquete + i) = *(tramaIP.datos + j);
}

/*********************************************** FUNCIONES TABLA NAT ***********************************************/
void insertarNodoNAT(NODO_NAT **cabeza, DATO_NAT dato){
    NODO_NAT *nuevo = (NODO_NAT *)malloc(sizeof(NODO_NAT));
    nuevo->dato = dato;
    nuevo->sig = *cabeza;
    *cabeza = nuevo;
}

void borrarListaNAT(NODO_NAT **cabeza){
    NODO_NAT *temp;
    while(*cabeza != NULL){
        temp = *cabeza;
        *cabeza = temp->sig;
        temp->sig = NULL;
        free(temp);
    }
}

int compararDirIp(BYTE_T dirIP_1[4], BYTE_T dirIP_2[4]){
    int i;
    for(i=0; i < 4; i++)
        if(dirIP_1[i] != dirIP_2[i])
            return 0;
    return 1;
}

int compararDirMAC(BYTE_T dirMAC_1[6], BYTE_T dirMAC_2[6]){
    int i;
    for(i=0; i < 4; i++)
        if(dirMAC_1[i] != dirMAC_2[i])
            return 0;
    return 1;
}

void borrarNodoNAT(NODO_NAT **cabeza, BYTE_T dirIp[4]){
    NODO_NAT *actual, *anterior;
    int encontrado = 0;
    actual = *cabeza;
    anterior = NULL;

    while ( (actual != NULL) && !encontrado)
    {
        DATO_NAT temp = actual->dato;
        encontrado = (compararDirIp(dirIp,temp.dirIP) || compararDirIp(dirIp,temp.dirIPVirtual));
        if( !encontrado ){
            anterior = actual;
            actual = actual->sig;
        }
    }
    if( actual != NULL ){
        if(actual == *cabeza)
            *cabeza = actual->sig;
        else
            anterior->sig = actual->sig;

        free(actual);
    }
}

NODO_NAT *buscarNodoNAT(NODO_NAT *cabeza, BYTE_T dirIp[]){
    NODO_NAT *ptr = cabeza;
    while (ptr != NULL)
    {
        DATO_NAT temp = ptr->dato;
        if(compararDirIp(dirIp,temp.dirIP) || compararDirIp(dirIp,temp.dirIPVirtual))
            return ptr;
        ptr = ptr->sig;
    }
    return NULL;
}

void imprimirTablaNAT(NODO_NAT *cab){

    while(cab != NULL){
        DATO_NAT dato = cab->dato;
        int i;
        printf(SEPARADOR);
        printf("DIR IP:");
        for(i=0; i<4; i++)
            printf("%d.",*(dato.dirIP + i));
        printf("\nDIR IP VIRTUAL:");
        for(i=0; i<4; i++)
            printf("%d.",*(dato.dirIPVirtual + i));

        printf("\nDIR MAC:");
        for(i=0; i<4; i++)
            printf("%x  ",*(dato.dirMAC + i));
        printf(SEPARADOR);
        cab = cab->sig;
    }
}
/*********************************************** FUNCIONES DEL POOL ***********************************************/
void crearPool(NODO_POOL **cab){
    int i;
    BYTE_T dirIP[4];
    dirIP[0] = 10;
    dirIP[1] = 0;
    dirIP[2] = 0;

    for(i=0; i < 10; i++)
    {
        dirIP[3] = 100 + i;
        insertarDireccionPool(cab,dirIP);
    }
}

void insertarDireccionPool(NODO_POOL **cab, BYTE_T *dirIP){
    int i; // Variable de iteración
    NODO_POOL *nuevo = (NODO_POOL *)malloc(sizeof(NODO_POOL));
    nuevo->sig = NULL;
    for(i = 0; i < 4; i++)
        *(nuevo->dirIP + i) = *(dirIP + i);

    if(*cab == NULL){
        *cab = nuevo;
        return;
    }

    NODO_POOL *temp = *cab;
    while(temp->sig != NULL){
        temp = temp->sig;
    }
    temp->sig = nuevo;
}

void imprimirPool(NODO_POOL **cab){
    NODO_POOL *temp = *cab;

    while(temp != NULL){
        int i;
        for(i=0; i < 4; i++){
            printf("%d.",*(temp->dirIP + i));
        }
        printf("\n");
        temp = temp->sig;
    }
}

void obetnerDirIpPool(NODO_POOL **cab, BYTE_T *dirIP){
    NODO_POOL *temp = *cab;
    if(temp != NULL){
        (*cab) = temp->sig;
        temp->sig = NULL;
        int i;
        for(i=0; i < 4; i++)
            *(dirIP+i) = *(temp->dirIP + i);
        free(temp);
    }
}

void liberarPool(NODO_POOL **cab){
    while(*cab != NULL){
        BYTE_T temp[4];
        obetnerDirIpPool(cab,temp);
        int i;
        for(i=0; i < 4; i++){
            printf("%d.",*(temp + i));
        }
        printf("\tLIBERADA\n");
    }
}