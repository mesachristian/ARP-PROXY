//COMPILE:
// Ctrl + shift + b para crear el archivo ejecutable run.exe
// gcc main_threads.c -o run -IH:\Escritorio\8_Semestre\Comunicacion_y_redes\ARP_PROXY\npcap-sdk-1.05\Include -L. -lwpcap -lpacket

#include "tramas.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define SEPARADOR "\n==================================================\n"
#define LOCAL_INTERFACES "rpcap//:"
#define RECEIVED_PACKET_SIZE 1518
#define TIMEOUT_PAQUETES 1000

int encontrarAdaptadorDeRed(pcap_if_t **);
void manejadorPaquetes(u_char *, const struct pcap_pkthdr *, const u_char *);
void manejadorPaquetesWIFI(u_char *param, const struct pcap_pkthdr *encabezado, const u_char *data);

void suplantacionDeDirMAC(TRAMA_ARP tramaARP);
void suplantacionIP(TRAMA_IPV4 tramaIP, DATO_NAT datoNAT, unsigned char redLocal);

int verificarDirecciones(BYTE_T *dirOrigen, BYTE_T *dirDestino, BYTE_T *mascara);
void imprimirTablaNAT(NODO_NAT *cab);

char errbuff[PCAP_ERRBUF_SIZE]; // Este buffer guardará posibles errores encotrados en el uso de funciones

NODO_POOL *poolDirecciones = NULL;
NODO_NAT *tablaNAT;

BYTE_T IP_PRUEBA[4] = {192,168,0,1};

//BYTE_T MAC_PROXY[6] = {0x30, 0x52, 0xcb, 0xc7, 0xdf, 0x3b};
BYTE_T MAC_PROXY[6] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
BYTE_T DIR_RED[4] = {20,0,0,0}; // DIRECCIÓN DE RED
BYTE_T mascara[4] = {255,255,255,0}; // MASCARA DE RED
BYTE_T PUERTA_ENLACE[4] = {20,0,0,1}; // PUERTA DE ENLACE

BYTE_T MAC_PUERTA_ENLACE[6] = {0x08,0x08,0x08,0x08,0x08,0x08}; // DIRECCION MAC PUERTA DE ENLACE

// PARTE DE HILOS
// Se necesitan dos hilos de ejecución para escuchar en los dos adaptadores de red
pcap_t *adaptador_eth; // Adaptador para trafico en ethernet
pcap_t *adaptador_wifi; // Adaptador para trafico WiFi

pthread_t hiloAdaptadorEthernet;
pthread_t hiloAdaptadorWifi;

void *escuchaPromiscua(void *adaptador){
    pcap_t *fp = (pcap_t *) adaptador;
    pcap_loop(fp,0,manejadorPaquetes,NULL);
}

void *escuchaPromiscua_WIFI(void *adaptador){
    pcap_t *fp = (pcap_t *) adaptador;
    pcap_loop(fp,0,manejadorPaquetesWIFI,NULL);
}

int main()
{
    tablaNAT = NULL; // Inicializar la tabla NAT

    crearPool(&poolDirecciones); // Crear un pool de direcciones para suplantación

    // 1. Elegir el adaptador de red para escuchar su trafico
    pcap_if_t *adaptador_e, *adaptador_w;

    while (encontrarAdaptadorDeRed(&adaptador_e) != 0);
    printf("SELECCIONADO PARA ETHERNET: %s (%s)\n", adaptador_e->name, adaptador_e->description);

    /***
     * Parametros pcap_open:
     * nombre del adaptador
     * Total de bytes que se almacenan de cada paquete recibido
     * Banderas: Se pone en modo promiscuo para que reciba todo el trafico
     * Timeout de lectura en milisegundos
     * Autorizaciones requeridas: NULL
     * Error buffer
    */
    adaptador_eth = pcap_open(  adaptador_e->name, 
                                RECEIVED_PACKET_SIZE,
                                PCAP_OPENFLAG_PROMISCUOUS,
                                TIMEOUT_PAQUETES,
                                NULL,
                                errbuff);

    if (adaptador_eth == NULL)
    {
        printf("%s",errbuff);
        return 1;
    }

    while (encontrarAdaptadorDeRed(&adaptador_w) != 0);
    printf("SELECCIONADO PARA WIFI: %s (%s)\n", adaptador_w->name, adaptador_w->description);

    adaptador_wifi = pcap_open(  adaptador_w->name, 
                                RECEIVED_PACKET_SIZE,
                                PCAP_OPENFLAG_MAX_RESPONSIVENESS,
                                TIMEOUT_PAQUETES,
                                NULL,
                                errbuff);

    if (adaptador_wifi == NULL)
    {
        printf("%s",errbuff);
        return 1;
    }

    pthread_create(&hiloAdaptadorEthernet,NULL,&escuchaPromiscua,adaptador_eth);
    pthread_create(&hiloAdaptadorWifi,NULL,&escuchaPromiscua_WIFI,adaptador_wifi);

    pthread_join(hiloAdaptadorEthernet,NULL);
    pthread_join(hiloAdaptadorWifi,NULL);

    liberarPool(&poolDirecciones);
    borrarListaNAT(&tablaNAT);

    return 0;
}

int encontrarAdaptadorDeRed(pcap_if_t **adaptador)
{

    pcap_if_t *dispositivos; // Lista para todos los dispositivos
    pcap_if_t *d;
    int seleccion;
    /***
     * Source: 'rpcap//:' para adaptadores locales
     * auth: NULL : No se necesita autorización ya que se hace en el local host 
     * devices: Se pasa un apuntador a los dispositivos
     * errbuff: Se pasa el errbuff
    */
    if (pcap_findalldevs_ex(LOCAL_INTERFACES, NULL, &dispositivos, errbuff) == -1)
    {
        printf("Error encontrando los dispositivos");
        return -1;
    }

    int contadorDispositivos = 0;

    for (d = dispositivos; d != NULL; d = d->next)
    {
        printf("%d. %s (%s)\n", ++contadorDispositivos, d->name, d->description);
    }

    printf("Elija un dispositivo entre 1 e %d: \n>", contadorDispositivos);
    scanf("%d", &seleccion);

    if (seleccion < 1 || seleccion > contadorDispositivos)
    {
        printf("Seleccione un dispositivo en el rango establecido!");
        return -1;
    }

    for (d = dispositivos; d != NULL; d = d->next)
    {
        if ((--seleccion) == 0)
            break;
    }

    *adaptador = d;

    pcap_freealldevs(dispositivos); // Cerrar todos los dispositivos abiertos

    return 0;
}

void manejadorPaquetes(u_char *param, const struct pcap_pkthdr *encabezado, const u_char *data)
{
    
    TRAMA_ETHERNET tramaEth0;
    crearTramaEthernet(&tramaEth0, (BYTE_T *)data);
    int i;

    if (tramaEth0.tipo_lon[0] == 8 && tramaEth0.tipo_lon[1] == 6) // Filtrar tramas ARP
    {
        TRAMA_ARP tramaARP;
        crearTramaARP(&tramaARP, tramaEth0.datos);
        
        if (tramaARP.opcode[0] == 0 && tramaARP.opcode[1] == 1) // Obtener todas las tramas de request
        {
            if (verificarDirecciones(tramaARP.dirProtocoloOrigen,tramaARP.dirProtocoloDestino,mascara) == 0)
            {
                // Si entra aca es porque se necesita el uso del servidor proxy ARP
                if(compararDirIp(tramaARP.dirProtocoloDestino,IP_PRUEBA) == 0){
                    if(compararDirIp(tramaARP.dirProtocoloOrigen,IP_PRUEBA) == 0)
                    {
                        printf(SEPARADOR);
                        printf("Suplantacion ARP:\n");
                        imprimirTramaARP(&tramaARP);
                        printf(SEPARADOR);
                        suplantacionDeDirMAC(tramaARP);
                    }
                }
            }
        }
    }

    else if (tramaEth0.tipo_lon[0] == 8 && tramaEth0.tipo_lon[1] == 0) // Filtrar tramas IPv4
    {
        TRAMA_IPV4 tramaIP;
        crearTramaIPV4(&tramaIP,tramaEth0.datos);

        // 2. La trama IP se dirige afuera de la red local
        NODO_NAT *nodo = buscarNodoNAT(tablaNAT,tramaIP.ipOrigen);
        if( nodo != NULL ){
            DATO_NAT filaNAT = nodo->dato;
            // Verificar que la trama se diriga afuera de la red
            BYTE_T redDestino[4];
            for(i=0; i < 4; i++){
                redDestino[i] = (*(tramaIP.ipDestino + i)) & (*(mascara + i));
            }
            if( compararDirIp(redDestino,DIR_RED) == 0 ){ // La trama de dirige a otra red
                printf(SEPARADOR);
                printf("Suplantacion IP para otra red:\n");
                imprimirTramaIPV4(&tramaIP);
                printf(SEPARADOR);
                suplantacionIP(tramaIP,filaNAT,(unsigned char) 0x00);
            }
        }
    }
}

void manejadorPaquetesWIFI(u_char *param, const struct pcap_pkthdr *encabezado, const u_char *data)
{
    
    TRAMA_ETHERNET tramaEth0;
    crearTramaEthernet(&tramaEth0, (BYTE_T *)data);
    int i;
    
    if (tramaEth0.tipo_lon[0] == 8 && tramaEth0.tipo_lon[1] == 0) // Filtrar tramas IPv4
    {
        TRAMA_IPV4 tramaIP;
        crearTramaIPV4(&tramaIP,tramaEth0.datos);
        
        // 1. La trama IP se dirige a una de las direcciones del pool
        NODO_NAT *nodo = buscarNodoNAT(tablaNAT,tramaIP.ipDestino);
        if( nodo != NULL ){
            // Verificar que sea la IP virtual la destinataria
            DATO_NAT filaNAT= nodo->dato; 
            if( compararDirIp(tramaIP.ipDestino,filaNAT.dirIPVirtual) ){
                printf(SEPARADOR);
                printf("Suplantacion IP red local:\n");
                imprimirTramaIPV4(&tramaIP);
                printf(SEPARADOR);
                suplantacionIP(tramaIP,filaNAT,(unsigned char) 0x01);
            }
        }
    }
}

/***
 * Esta función verifica direcciones IP devolviendo un 0 cuando se requiera
 * el uso del servidor proxy ARP
 */
int verificarDirecciones(BYTE_T *dirOrigen, BYTE_T *dirDestino, BYTE_T *mascara){
    int i;
    // 1. Verificar sí la dirección de origen pertenece a la red
    BYTE_T redOrigen[4];
    BYTE_T redDestino[4];

    for(i=0; i < 4; i++){
        redOrigen[i] = (*(dirOrigen + i)) & (*(mascara + i));
        redDestino[i] = (*(dirDestino + i)) & (*(mascara + i));
    }

    if( compararDirIp(redOrigen,DIR_RED) == 0 && compararDirIp(redOrigen,redDestino) ){
        // Cuando la direccion no pertenezca a la red e intente hacer una peticion a una direccion
        // que pertenecería a su red se debe usar el servidor proxy ARP.
        return 0;
    }
    return 1; // En caso de que no pertenezca se debe hacer la suplantación
}

void suplantacionDeDirMAC(TRAMA_ARP tramaARP)
{
    int i;
    
    NODO_NAT *dato = buscarNodoNAT(tablaNAT,tramaARP.dirProtocoloOrigen);
    if(dato == NULL){
        // AGREGAR EL NUEVO DISPOSITIVO A LA TABLA NAT
        DATO_NAT datoNAT;
        for(i=0; i < 6; i++)
            *(datoNAT.dirMAC + i) = *(tramaARP.dirHardwareOrigen + i); // GUARDAR MAC ORIGEN

        for(i=0; i < 4; i++)
            *(datoNAT.dirIP + i) = *(tramaARP.dirProtocoloOrigen + i); // GUARADAR IP ORIGEN

        obetnerDirIpPool(&poolDirecciones,datoNAT.dirIPVirtual); // ASIGNAR UNA IP DEL POOL

        insertarNodoNAT(&tablaNAT,datoNAT); // Insertar a la tabla NAT
    }

    u_char packet[60];                                // 60 es el tamaño minimo para que sea una trama ethernet valida
    armarPaqueteReplyARP(tramaARP.dirHardwareOrigen,  // La direccion de origen de la trama se vuelve la de destino
                         MAC_PROXY,                   // Esta es la dirección del servidor PROXY ARP-NAT
                         tramaARP.dirProtocoloOrigen, // Direccion ip destino
                         tramaARP.dirProtocoloDestino,// Suplantar la IP origen
                         (BYTE_T *)packet);

    if (pcap_sendpacket(adaptador_eth, packet, 60) != 0) // Enviar la trama correspondiente
    {
        printf("Error enviando la respuesta ARP\n");
        return;
    }
}

void suplantacionIP(TRAMA_IPV4 tramaIP, DATO_NAT datoNAT, unsigned char redLocal){
    unsigned int tamTotalTramaIp = tramaIP.tamTotal[1];
    tamTotalTramaIp |= (unsigned int)(tramaIP.tamTotal[0] << 8);

    // Modificar la trama IP (solamente la IP de destino) 
    u_char packet[14 + tamTotalTramaIp];

    int i;
    for(i=0; i < 4; i++){
        if( redLocal ){ // El paquete es para la RED local
            tramaIP.ipDestino[i] = datoNAT.dirIP[i]; // Se cambia la IP de destino
            
        }else{ // El mensaje es para una red externa
            tramaIP.ipOrigen[i] = datoNAT.dirIPVirtual[i]; // Se cambia la IP de destino
        }
    }

    if( redLocal ){
        armarPaqueteIP( MAC_PROXY, // MAC de origen
                    datoNAT.dirMAC, // MAC de destino
                    tramaIP, // Enviar la trama IP modificada 
                    packet ); // Bytes para enviar
        // ENVIAR TRAMA
        if (pcap_sendpacket(adaptador_eth, packet, 14+tamTotalTramaIp) != 0) // Enviar la trama correspondiente
        {
            printf("Error enviando la respuesta ARP\n");
            return;
        }
    }else{
        armarPaqueteIP( MAC_PROXY, // MAC de origen
                    MAC_PUERTA_ENLACE, // MAC de LA MAQUINA VIRTUAL
                    tramaIP, // Enviar la trama IP modificada 
                    packet ); // Bytes para enviar
        // ENVIAR TRAMA
        if (pcap_sendpacket(adaptador_wifi, packet, 14+tamTotalTramaIp) != 0) // Enviar la trama correspondiente
        {
            printf("Error enviando la respuesta ARP\n");
            return;
        }
    }
}