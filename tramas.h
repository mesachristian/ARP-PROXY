#ifndef TRAMAS_H
#define TRAMAS_H

#define MAX_DATOS 1500 // Una trama ethernet tiene maximo 1500 byts de datos
#define TAM_TRAMA_ARP 42
#define SEPARADOR "\n==================================================\n"

typedef unsigned char BYTE_T;

typedef struct nodo_p{
    BYTE_T dirIP[4];
    struct nodo_p *sig;
}NODO_POOL;

typedef struct
{
    BYTE_T dir_destino[6];
    BYTE_T dir_origen[6];
    BYTE_T tipo_lon[2];
    BYTE_T *datos;    
}TRAMA_ETHERNET;

typedef struct ARP
{
    BYTE_T tipoHardware[2];
    BYTE_T tipoProtocolo[2];
    BYTE_T longitudHardware;
    BYTE_T longitudProtocolo;
    BYTE_T opcode[2]; // Codigo de operación
    BYTE_T *dirHardwareOrigen;
    BYTE_T *dirProtocoloOrigen;
    BYTE_T *dirHardwareDestino;
    BYTE_T *dirProtocoloDestino;
}TRAMA_ARP;

typedef struct IPV4{
    BYTE_T version_tamEncabezado;
    BYTE_T serviciosDiferenciados;
    BYTE_T tamTotal[2];
    BYTE_T identificacion[2];
    BYTE_T banderas_offset[2];
    BYTE_T tiempoDeVida;
    BYTE_T protocolo;
    BYTE_T checkSumEncabezado[2];
    BYTE_T ipOrigen[4];
    BYTE_T ipDestino[4];
    BYTE_T *datos;
}TRAMA_IPV4;

typedef struct{
    BYTE_T dirIP[4];
    BYTE_T dirMAC[6];
    BYTE_T dirIPVirtual[4];
}DATO_NAT;

typedef struct nodo{
    DATO_NAT dato;
    struct nodo *sig;
}NODO_NAT;

typedef struct{
    BYTE_T dirIP[4];
    int mascara;
}DIRECCION_DE_RED;

// FUNCIONES DE TABLA NAT
int compararDirIp(BYTE_T dirIP_1[4], BYTE_T dirIP_2[4]);
int compararDirMAC(BYTE_T dirMAC_1[6], BYTE_T dirMAC_2[6]);
void insertarNodoNAT(NODO_NAT **cabeza, DATO_NAT dato);
void borrarListaNAT(NODO_NAT **cabeza);
void borrarNodoNAT(NODO_NAT **cabeza, BYTE_T dirIp[4]);
NODO_NAT *buscarNodoNAT(NODO_NAT *cabeza, BYTE_T dirIp[]);
void imprimirTablaNAT(NODO_NAT *cab);

// FUNCIONES DE ETHERNET
void crearTramaEthernet(TRAMA_ETHERNET *trama, BYTE_T *datos);
void imprimirTramaEthernet(TRAMA_ETHERNET trama, int longitudTrama);

// FUNCIONES DE ARP
void crearTramaARP(TRAMA_ARP *trama, BYTE_T *datos);
void imprimirTramaARP(TRAMA_ARP *trama);
void armarPaqueteReplyARP(BYTE_T *dirMACDestino, BYTE_T *dirMACOrigen, BYTE_T *dirIPDestino, BYTE_T *dirIPOrigen, BYTE_T *paquete);

// FUNCIONES DE IPV4
void crearTramaIPV4(TRAMA_IPV4 *trama, BYTE_T *datos);
void imprimirTramaIPV4(TRAMA_IPV4 *trama);
void armarPaqueteIP(BYTE_T *macOrigen,BYTE_T *macDestino,TRAMA_IPV4 tramaIP, BYTE_T *paquete);

/// POOL DE DIRECCIONES
void crearPool(NODO_POOL **cab);
void insertarDireccionPool(NODO_POOL **cab, BYTE_T *dirIP);
void imprimirPool(NODO_POOL **cab);
void liberarPool(NODO_POOL **cab);
void obetnerDirIpPool(NODO_POOL **cab, BYTE_T *dirIP);

#endif