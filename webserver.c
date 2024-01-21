#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/sha.h>

#include "data.h"
#include "http.h"
#include "util.h"

#define MAX_RESOURCES 100

// Unsere Datenbank
struct tuple resources[MAX_RESOURCES] = {
    {"/static/foo", "Foo", sizeof "Foo" - 1},
    {"/static/bar", "Bar", sizeof "Bar" - 1},
    {"/static/baz", "Baz", sizeof "Baz" - 1}
};

// Struktur um Node Informationen wie ID, IP und Port zu speichern. 
typedef struct{
    uint16_t id;
    char ip[INET_ADDRSTRLEN];
    int port;
}NodeInfo;

// Struktur um Informationen über Pred, Peer und Succ Nodes zu speichern.
typedef struct{
    NodeInfo pred;
    NodeInfo peer;
    NodeInfo succ;
}DHTNodeInfo;

// Globale Struktur um von überall auf diese Informationen zugreifen zu können.
DHTNodeInfo twoNodeDHTInfo;

// Struktur um eine UDP Message zu verarbeiten. 
typedef struct {
    uint8_t messageType;
    uint16_t hashId;
    uint16_t nodeId;
    char nodeIp[INET_ADDRSTRLEN];
    int nodePort;
} UdpMessage;

// Maximale 10 DHT Entries für unsere kleine DHT - Datenbank
#define MAX_DHT_ENTRIES 10

// Ein Eintrag in unsere DHT-Datenbank 
typedef struct {
    uint16_t id;             // Die Hash-ID der URI.
    NodeInfo node;           // Informationen über die verantwortliche Node.
} DHTEntry;

// Temporäre globale Variable, welche die gehashte URI zwischenspeichert. 
uint16_t temp_global_udp_uri; // Globale Hash-ID der URI. 

// Unsere DHT-Datenbank. DHT Entries werden als Tupel aus gehashter URI und der dafür zuständigen Node gespeichert. 
DHTEntry dhtEntries[MAX_DHT_ENTRIES];
int dhtEntriesCount = 0;

// Diese Funktion dient hauptsächlich zum Debuggen und gibt die aktuellen DHT-Einträge aus.
void printDHTEntries(void) {
    fprintf(stderr, "Aktuelle DHT-Einträge:\n");  // Ausgabe der Überschrift für die DHT-Einträge.
    for (int i = 0; i < dhtEntriesCount; i++) {
        fprintf(stderr, "Eintrag %d: Hash ID: %u, Knoten-IP: %s, Knoten-Port: %d\n", i, dhtEntries[i].id, dhtEntries[i].node.ip, dhtEntries[i].node.port);
        // Ausgabe der Informationen für jeden DHT-Eintrag, einschließlich Hash-ID, Knoten-IP und Knoten-Port.
    }
    fflush(stderr);  // Sicherstellen, dass die Ausgabe sofort aktualisiert wird.
}


/**
 * Aktualisiert einen DHT-Eintrag für eine gegebene Hash-ID und Node-Information.
 *
 * @param hashId Die Hash-ID des zu aktualisierenden Eintrags.
 * @param node Die Node-Informationen, die für die Aktualisierung verwendet werden sollen.
 *
 * @return Gibt einen Zeiger auf das erste ungenutzte Byte im Buffer nach der Aktualisierung zurück.
 * @example updateDHTEntry(1234, nodeInfo):
 *          Aktualisiert einen vorhandenen Eintrag oder fügt einen neuen Eintrag hinzu und gibt einen Zeiger auf das aktualisierte Buffer zurück.
 */
void updateDHTEntry(uint16_t hashId, NodeInfo node) {

    printDHTEntries(); // Ausgabe der aktuellen DHT-Einträge vor der Aktualisierung.

    // Durchlaufen der vorhandenen DHT-Einträge, um den Eintrag mit der gegebenen Hash-ID zu finden.
    for (int i = 0; i < dhtEntriesCount; i++) {
        if (dhtEntries[i].id == hashId) {
            fprintf(stderr, "Vorhandenen Eintrag gefunden, Aktualisierung...\n"); // Ausgabe, wenn ein vorhandener Eintrag gefunden wird.
            fflush(stderr); // Sicherstellen, dass die Ausgabe sofort aktualisiert wird.
            dhtEntries[i].node = node; // Aktualisierung der Knoteninformationen im Eintrag.
            printDHTEntries(); // Ausgabe der aktualisierten DHT-Einträge nach der Aktualisierung.
            return; // Die Funktion wird beendet, nachdem der Eintrag aktualisiert wurde.
        }
    }

    // Wenn die Hash-ID nicht gefunden wurde und noch Platz für neue Einträge vorhanden ist.
    if (dhtEntriesCount < MAX_DHT_ENTRIES) {
        fprintf(stderr, "Neuen Eintrag hinzufügen...\n"); // Ausgabe, wenn ein neuer Eintrag hinzugefügt wird.
        fflush(stderr); // Sicherstellen, dass die Ausgabe sofort aktualisiert wird.
        dhtEntries[dhtEntriesCount].id = hashId; // Hinzufügen der neuen Hash-ID.
        dhtEntries[dhtEntriesCount].node = node; // Hinzufügen der neuen Knoteninformationen.
        dhtEntriesCount++; // Erhöhen der Anzahl der DHT-Einträge.
    } 
    // Wenn kein Platz mehr für neue Einträge vorhanden ist, müssen bestehende Einträge verschoben werden.
    else {
        fprintf(stderr, "Kein Platz mehr, Verschieben der Einträge...\n"); // Ausgabe, wenn kein Platz mehr vorhanden ist.
        fflush(stderr); // Sicherstellen, dass die Ausgabe sofort aktualisiert wird.
        // Memmove wird verwendet, um die bestehenden Einträge zu verschieben.
        memmove(&dhtEntries[0], &dhtEntries[1], sizeof(DHTEntry) * (MAX_DHT_ENTRIES - 1));
        dhtEntries[MAX_DHT_ENTRIES - 1].id = hashId; // Hinzufügen der neuen Hash-ID am Ende.
        dhtEntries[MAX_DHT_ENTRIES - 1].node = node; // Hinzufügen der neuen Knoteninformationen am Ende.
    }

    printDHTEntries(); // Ausgabe der aktualisierten DHT-Einträge nach der Aktualisierung.
}


/**
 * Sucht nach einem DHT-Eintrag anhand einer gegebenen Hash-ID.
 *
 * @param hashId Die Hash-ID des gesuchten Eintrags.
 *
 * @return Gibt einen Zeiger auf die Knoteninformationen des gefundenen Eintrags zurück, oder NULL, wenn kein Eintrag gefunden wurde.
 * @example findDHTEntry(1234):
 *          Sucht nach einem DHT-Eintrag mit der Hash-ID 1234 und gibt einen Zeiger auf die Knoteninformationen zurück, falls gefunden, ansonsten NULL.
 */
NodeInfo* findDHTEntry(uint16_t hashId) {
    fprintf(stderr, "Suche nach DHT-Eintrag für Hash-ID: %u\n", hashId); // Ausgabe der Suchinformationen für Debugging-Zwecke.
    fflush(stderr); // Sicherstellen, dass die Ausgabe sofort aktualisiert wird.
    
    // Durchlaufen der vorhandenen DHT-Einträge, um den Eintrag mit der gegebenen Hash-ID zu finden.
    for (int i = 0; i < dhtEntriesCount; i++) {
        if (dhtEntries[i].id == hashId) {
            fprintf(stderr, "Eintrag gefunden an Index %d\n", i); // Ausgabe, wenn ein Eintrag gefunden wird.
            fflush(stderr); // Sicherstellen, dass die Ausgabe sofort aktualisiert wird.
            return &dhtEntries[i].node; // Rückgabe eines Zeigers auf die Knoteninformationen des gefundenen Eintrags.
        }
    }
    
    fprintf(stderr, "Kein Eintrag gefunden für Hash-ID: %u\n", hashId); // Ausgabe, wenn kein Eintrag gefunden wird.
    fflush(stderr); // Sicherstellen, dass die Ausgabe sofort aktualisiert wird.
    return NULL; // Rückgabe von NULL, wenn kein Eintrag gefunden wird.
}




/**
 * Berechnet einen 16-Bit-Hash-Wert für eine gegebene URI-Zeichenfolge unter Verwendung der SHA-256-Hashfunktion.
 *
 * @param uri Die URI-Zeichenfolge, für die der Hash-Wert berechnet werden soll.
 *
 * @return Gibt den 16-Bit-Hash-Wert für die URI zurück.
 * @example hash_uri("/static/foo"):
 *          Berechnet den SHA-256-Hash der URI "/static/foo" und gibt die ersten beiden Bytes des Digests als 16-Bit-Hash-Wert zurück.
 */
uint16_t hash_uri(const char* uri) {
    uint8_t digest[SHA256_DIGEST_LENGTH];

    // Die SHA-256-Hashfunktion wird auf den URI angewendet, um einen Digest zu erstellen.
    SHA256((uint8_t *)uri, strlen(uri), digest);

    // Wir verwenden hier nur die ersten zwei Bytes des Digests, um einen 16-Bit-Hash-Wert zu erstellen.
    // Beachten Sie, dass diese Methode eine sehr einfache Hash-Funktion darstellt und in der Praxis
    // möglicherweise nicht ausreichend ist, um Kollisionen zu vermeiden.
    return htons(*((uint16_t *)digest));
}


/**
 * Konvertiert eine IP-Adresse in dezimaler Form in einen 32-Bit-Ganzzahlwert.
 *
 * @param node Ein Zeiger auf die NodeInfo-Struktur, die die IP-Adresse enthält.
 *
 * @return Gibt den dezimalen 32-Bit-Wert der IP-Adresse zurück oder EXIT_FAILURE im Fehlerfall.
 * @example convertIPtoDecimal(&nodeInfo):
 *          Konvertiert die IP-Adresse aus der übergebenen NodeInfo-Struktur in einen dezimalen 32-Bit-Wert und gibt ihn zurück.
 */
uint32_t convertIPtoDecimal(NodeInfo *node){
    struct in_addr ip_addr;

    // Die IP-Adresse wird aus der NodeInfo-Struktur in eine dezimale Form konvertiert.
    if (inet_pton(AF_INET, node->ip, &ip_addr) != 1) {
        fprintf(stderr, "Fehler beim Konvertieren der IP-Adresse\n"); // Ausgabe im Fehlerfall.
        return EXIT_FAILURE; // Rückgabe von EXIT_FAILURE im Fehlerfall.
    }

    return ntohl(ip_addr.s_addr); // Rückgabe des dezimalen 32-Bit-Werts der IP-Adresse.
}


/**
 * Generiert eine Nachricht für die Weiterleitung basierend auf dem angegebenen Grund (reason) und einer UdpMessage.
 *
 * @param byte_array Ein Zeiger auf das Byte-Array, in dem die generierte Nachricht gespeichert wird.
 * @param reason Der Grund für die Generierung der Nachricht ("Repack" oder andere).
 * @param message Ein Zeiger auf die UdpMessage, die für die Generierung verwendet wird.
 *
 * @return Die generierte Nachricht im Byte-Array.
 * @example generateForward(byteArray, "Repack", &udpMessage):
 *          Generiert eine Weiterleitungs-Nachricht basierend auf dem Grund "Repack" und einer UdpMessage und speichert sie im Byte-Array.
 */
void generateForward(uint8_t *byte_array, const char *reason, UdpMessage *message) {

    if (strcmp(reason, "Repack") == 0) {
        fprintf(stderr, "Nachricht wird neu verpackt\n");
        fflush(stderr);

        // Rekonstruktion der ursprünglichen Nachricht
        byte_array[0] = message->messageType;
        fprintf(stderr, "Nachrichtentyp: %u\n", message->messageType);
        fflush(stderr);

        byte_array[1] = message->hashId >> 8 & 0xFF;
        byte_array[2] = message->hashId & 0xFF;
        fprintf(stderr, "Hash-ID: %u\n", message->hashId);
        fflush(stderr);

        byte_array[3] = message->nodeId >> 8 & 0xFF;
        byte_array[4] = message->nodeId & 0xFF;
        fprintf(stderr, "Knoten-ID: %u\n", message->nodeId);
        fflush(stderr);

        // Umwandlung der IP-Adresse von String in Dezimal
        uint32_t decimal_ip = convertIPtoDecimal(&twoNodeDHTInfo.succ);
        fprintf(stderr, "Dezimale IP: %u\n", decimal_ip);
        fflush(stderr);

        byte_array[5] = decimal_ip >> 24 & 0xFF;
        byte_array[6] = decimal_ip >> 16 & 0xFF;
        byte_array[7] = decimal_ip >> 8 & 0xFF;
        byte_array[8] = decimal_ip & 0xFF;

        // Port
        byte_array[9] = message->nodePort >> 8 & 0xFF;
        byte_array[10] = message->nodePort & 0xFF;
        fprintf(stderr, "Knoten-Port: %u\n", message->nodePort);
        fflush(stderr);
    }
}



/**
 * Generiert eine Nachricht im Byte-Array basierend auf dem angegebenen Grund (reason) und einer URI-Hash-ID.
 *
 * @param byte_array Ein Zeiger auf das Byte-Array, in dem die generierte Nachricht gespeichert wird.
 * @param reason Der Grund für die Generierung der Nachricht ("Lookup", "Lookup_Reply_Self", "Lookup_Reply_Succ" oder andere).
 * @param uri_hash Die Hash-ID der URI, die in der Nachricht verwendet wird.
 *
 * @return Die generierte Nachricht im Byte-Array.
 * @example generateMessage(byteArray, "Lookup", 1234):
 *          Generiert eine Nachricht basierend auf dem Grund "Lookup", einer URI-Hash-ID und speichert sie im Byte-Array.
 */
void generateMessage(uint8_t *byte_array, const char *reason, uint16_t uri_hash){

    if (strcmp(reason, "Lookup") == 0){
        uint32_t decimal_ip = convertIPtoDecimal(&twoNodeDHTInfo.succ);
        byte_array[0] = 0; 
        byte_array[1] = (uri_hash >> 8) & 0xFF; 
        byte_array[2] = uri_hash & 0xFF; 
        byte_array[3] = ( (twoNodeDHTInfo.peer.id )>> 8) & 0xFF; 
        byte_array[4] = twoNodeDHTInfo.peer.id & 0xFF; 
        byte_array[5] = (decimal_ip >> 24) & 0xFF;  // Höchstes Byte von value4
        byte_array[6] = (decimal_ip >> 16) & 0xFF;  // Zweithöchstes Byte von value4
        byte_array[7] = (decimal_ip >> 8) & 0xFF;  // Dritthöchstes Byte von value4
        byte_array[8] = decimal_ip & 0xFF; 
        byte_array[9] = ((uint16_t)twoNodeDHTInfo.peer.port >> 8) & 0xFF;  // Höchstes Byte von value5
        byte_array[10] = (uint16_t)twoNodeDHTInfo.peer.port & 0xFF;

    }else if (strcmp(reason, "Lookup_Reply_Self") == 0){

        uint32_t decimal_ip = convertIPtoDecimal(&twoNodeDHTInfo.peer);
        byte_array[0] = 1; 
        byte_array[1] = (uri_hash >> 8) & 0xFF; 
        byte_array[2] = uri_hash & 0xFF; 
        byte_array[3] = ( (twoNodeDHTInfo.peer.id )>> 8) & 0xFF; 
        byte_array[4] = twoNodeDHTInfo.peer.id & 0xFF; 
        byte_array[5] = (decimal_ip >> 24) & 0xFF;  // Höchstes Byte von value4
        byte_array[6] = (decimal_ip >> 16) & 0xFF;  // Zweithöchstes Byte von value4
        byte_array[7] = (decimal_ip >> 8) & 0xFF;  // Dritthöchstes Byte von value4
        byte_array[8] = decimal_ip & 0xFF; 
        byte_array[9] = ((uint16_t)twoNodeDHTInfo.peer.port >> 8) & 0xFF;  // Höchstes Byte von value5
        byte_array[10] = (uint16_t)twoNodeDHTInfo.peer.port & 0xFF;

    }else if(strcmp(reason, "Lookup_Reply_Succ") == 0){
        uint32_t decimal_ip = convertIPtoDecimal(&twoNodeDHTInfo.succ);
        byte_array[0] = 1; 
        byte_array[1] = (uri_hash >> 8) & 0xFF; 
        byte_array[2] = uri_hash & 0xFF; 
        byte_array[3] = ( (twoNodeDHTInfo.succ.id )>> 8) & 0xFF; 
        byte_array[4] = twoNodeDHTInfo.succ.id & 0xFF; 
        byte_array[5] = (decimal_ip >> 24) & 0xFF;  // Höchstes Byte von value4
        byte_array[6] = (decimal_ip >> 16) & 0xFF;  // Zweithöchstes Byte von value4
        byte_array[7] = (decimal_ip >> 8) & 0xFF;  // Dritthöchstes Byte von value4
        byte_array[8] = decimal_ip & 0xFF; 
        byte_array[9] = ((uint16_t)twoNodeDHTInfo.succ.port >> 8) & 0xFF;  // Höchstes Byte von value5
        byte_array[10] = (uint16_t)twoNodeDHTInfo.succ.port & 0xFF;
    }
}


/**
 * Sendet eine UDP-Nachricht an das angegebene Ziel (NodeInfo).
 *
 * @param target Ein Zeiger auf die NodeInfo-Struktur des Zielknotens.
 * @param message Ein Zeiger auf das Byte-Array, das die zu sendende Nachricht enthält.
 *
 * @return Gibt 0 zurück, wenn die Nachricht erfolgreich gesendet wurde, oder -1 im Fehlerfall.
 * @example send_udp_message_to(&targetNode, byteArray):
 *          Sendet die UDP-Nachricht aus dem Byte-Array an den Zielknoten, gibt 0 bei Erfolg und -1 bei Fehlern zurück.
 */
int send_udp_message_to(NodeInfo* target, uint8_t *message){

    // Socket erstellen
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    if (sockfd < 0){
        perror("Socket-Erstellung fehlgeschlagen"); 
        return -1; 
    }

    // Zieladresse und Port konfigurieren
    struct sockaddr_in server_addr; 
    memset(&server_addr, 0, sizeof(server_addr)); 
    server_addr.sin_family = AF_INET; 
    server_addr.sin_port = htons(target->port); 

    if (inet_pton(AF_INET, target->ip, &server_addr.sin_addr) <= 0){
        perror("Ungültige Adresse / Adresse wird nicht unterstützt"); 
        return -1;
    }

    // Nachricht senden
    ssize_t sent_bytes = sendto(sockfd, message, 11, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)); 

    if (sent_bytes < 0 ){
        perror("sendto fehlgeschlagen! "); 
        close(sockfd); 
        return -1; 
    }

    // Socket schließen und Erfolg zurückgeben
    close(sockfd); 
    return 0; 
}


/**
 * Überprüft, ob der aktuelle Knoten für eine gegebene URI-Hash-ID verantwortlich ist.
 *
 * @param uri_hash Die Hash-ID der URI, für die die Verantwortlichkeit überprüft wird.
 *
 * @return Gibt 0 zurück, wenn der aktuelle Knoten für die URI verantwortlich ist,
 *         1 wenn der Nachfolgerknoten für die URI verantwortlich ist,
 *         oder 2, wenn der aktuelle Knoten oder der Nachfolgerknoten nicht verantwortlich ist.
 * @example is_responsible_for_uri(1234):
 *          Überprüft, ob der aktuelle Knoten für die URI mit der Hash-ID 1234 verantwortlich ist
 *          und gibt entsprechende Werte zurück (0, 1 oder 2).
 */
int is_responsible_for_uri(uint16_t uri_hash) {
    // Überprüfen, ob der URI-Hash im Verantwortungsbereich des aktuellen Knotens liegt.
    // Wenn der Hash kleiner oder gleich der eigenen ID ist oder größer als die Vorgänger-ID,
    // ist der Knoten für den URI verantwortlich, andernfalls nicht.
    if ((twoNodeDHTInfo.pred.id < uri_hash && uri_hash <= twoNodeDHTInfo.peer.id) ||
        ((twoNodeDHTInfo.pred.id > twoNodeDHTInfo.peer.id) && (uri_hash > twoNodeDHTInfo.pred.id || uri_hash <= twoNodeDHTInfo.peer.id))) {
        return 0; // Der aktuelle Knoten ist für die URI verantwortlich.
    } else if ((twoNodeDHTInfo.peer.id < uri_hash && uri_hash <= twoNodeDHTInfo.succ.id)||
        ((twoNodeDHTInfo.peer.id > twoNodeDHTInfo.succ.id) && (uri_hash > twoNodeDHTInfo.peer.id || uri_hash <= twoNodeDHTInfo.succ.id))) {
        return 1; // Der Nachfolgerknoten ist für die URI verantwortlich.
    }
    return 2; // Weder der aktuelle Knoten noch der Nachfolgerknoten sind für die URI verantwortlich.
}




/**
 * Sends an HTTP reply to the client based on the received request.
 *
 * @param conn      The file descriptor of the client connection socket.
 * @param request   A pointer to the struct containing the parsed request information.
 */
void send_reply(int conn, struct request* request) {
    char buffer[HTTP_MAX_SIZE];
    char *reply = buffer;

    fprintf(stderr, "Handling %s request for %s (%lu byte payload)\n", request->method, request->uri, request->payload_length);
    fflush(stderr); 

    uint16_t uri_hash = hash_uri(request->uri);
    
    int is_responsible = is_responsible_for_uri(uri_hash); 

    if (is_responsible == 0) {

    
        if (strcmp(request->method, "GET") == 0) {
            // Find the resource with the given URI in the 'resources' array.
            size_t resource_length;
            const char* resource = get(request->uri, resources, MAX_RESOURCES, &resource_length);

            if (resource) {
                sprintf(reply, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n%.*s", resource_length, (int) resource_length, resource);
            } else {
                reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            }
        } else if (strcmp(request->method, "PUT") == 0) {
            // Try to set the requested resource with the given payload in the 'resources' array.
            if (set(request->uri, request->payload, request->payload_length, resources, MAX_RESOURCES
            )) {
                reply = "HTTP/1.1 204 No Content\r\n\r\n";
            } else {
                reply = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
            }
        } else if (strcmp(request->method, "DELETE") == 0) {
            // Try to delete the requested resource from the 'resources' array
            if (delete(request->uri, resources, MAX_RESOURCES)) {
                reply = "HTTP/1.1 204 No Content\r\n\r\n";
            } else {
                reply = "HTTP/1.1 404 Not Found\r\n\r\n";
            }
        } else {
            reply = "HTTP/1.1 501 Method Not Supported\r\n\r\n";
        }

    } else if (is_responsible == 1) {

        // Peer knows, that successor ist verantwortlich.
        snprintf(reply, sizeof(buffer),
                 "HTTP/1.1 303 See Other\r\n"
                 "Location: http://127.0.0.1:%d%s\r\n"
                 "Content-Length: 0\r\n\r\n",
                 twoNodeDHTInfo.succ.port, request->uri);
    } else {

        NodeInfo* entryPtr = findDHTEntry(uri_hash);
            if (entryPtr == NULL) {
                // Wenn kein Eintrag gefunden wird, senden Sie die Lookup-Nachricht
                int retry_after_seconds = 1;
                snprintf(reply, sizeof(buffer),
                        "HTTP/1.1 503 Service Unavailable\r\n"
                        "Retry-After: %d\r\n"
                        "Content-Length: 0\r\n\r\n",
                        retry_after_seconds);
            
                // Kurzes Globales Zwischenspeichern der URI. 
                temp_global_udp_uri = uri_hash; 

                uint8_t byte_array[11];
                generateMessage(byte_array, "Lookup", uri_hash);
                send_udp_message_to(&twoNodeDHTInfo.succ, byte_array);

            } else {
                // Ein passender Eintrag wurde gefunden
                snprintf(reply, sizeof(buffer),
                        "HTTP/1.1 303 See Other\r\n"
                        "Location: http://%s:%d%s\r\n"
                        "Content-Length: 0\r\n\r\n",
                        entryPtr->ip, entryPtr->port, request->uri);
            }
    }

    if (send(conn, reply, strlen(reply), 0) == -1) {
        perror("send");
        close(conn);
    }
}

/**
 * Verarbeitet eine empfangene UDP-Nachricht und trifft entsprechende Maßnahmen basierend auf dem Nachrichtentyp.
 *
 * @param message Ein Zeiger auf die empfangene UdpMessage.
 * @example handle_udp_message(&receivedMessage):
 *          Verarbeitet die empfangene UDP-Nachricht und trifft entsprechende Maßnahmen basierend auf dem Nachrichtentyp.
 */
void handle_udp_message(UdpMessage *message) {

    fprintf(stderr, "Empfangene Nachricht - Typ: %u, Hash ID: %u, Knoten ID: %u, Knoten IP: %s, Knoten Port: %d\n",
            message->messageType, message->hashId, message->nodeId, message->nodeIp, message->nodePort);
    fflush(stderr);

    if (message->messageType == 0){
        int responsibility = is_responsible_for_uri(message->hashId);

        NodeInfo sender; 
        sender.id = message->nodeId;
        strncpy(sender.ip, message->nodeIp, INET_ADDRSTRLEN - 1);
        sender.ip[INET_ADDRSTRLEN - 1] = '\0';  // Sicherstellen, dass die Zeichenkette terminiert ist
        sender.port = message->nodePort;

        if (responsibility == 0) {

            uint8_t byte_array[11];
            generateMessage(byte_array, "Lookup_Reply_Self", message->nodeId);
            send_udp_message_to(&sender, byte_array);

        } else if (responsibility == 1) {

            uint8_t byte_array[11];
            generateMessage(byte_array, "Lookup_Reply_Succ", twoNodeDHTInfo.peer.id);
            send_udp_message_to(&sender, byte_array);

        } else {
            uint8_t byte_array[11];

            // Hier rufen Sie generateMessage mit den Werten aus der UdpMessage auf
            // Dies hängt von der genauen Implementierung Ihrer generateMessage-Funktion ab
            generateForward(byte_array, "Repack", message);

            // Weiterleiten der Nachricht an den Nachfolgeknoten
            send_udp_message_to(&twoNodeDHTInfo.succ, byte_array);
        }
    }else if(message->messageType == 0x01) {
        NodeInfo node; 
        node.id = message->nodeId;
        strncpy(node.ip, message->nodeIp, INET_ADDRSTRLEN - 1);
        node.ip[INET_ADDRSTRLEN - 1] = '\0';  // Sicherstellen, dass die Zeichenkette terminiert ist
        node.port = message->nodePort;
        updateDHTEntry(temp_global_udp_uri, node);

        // Zurücksetzen der Globalen URI auf 0. 
        temp_global_udp_uri = 0; 
    }
}




/**
 * Vorbereitet eine UdpMessage-Struktur basierend auf den empfangenen Bytes aus dem Puffer.
 *
 * @param buffer Ein Zeiger auf den Puffer, der die empfangenen Bytes enthält.
 * @param len Die Länge der empfangenen Bytes im Puffer.
 *
 * @return Die vorbereitete UdpMessage-Struktur mit den extrahierten Informationen aus dem Puffer.
 * @example UdpMessage msg = prepare_udp_message(receivedBuffer, receivedLength);
 *          Bereitet eine UdpMessage-Struktur vor, indem sie die empfangenen Bytes aus dem Puffer extrahiert.
 */
UdpMessage prepare_udp_message(uint8_t* buffer) {
    
    // Kopieren der ersten 11 Bytes aus dem Puffer in ein separates Byte-Array
    uint8_t byteArray[11];
    memcpy(byteArray, buffer, 11);

    // Extrahieren des ersten Bytes (Message Type)
    uint8_t message_Type = byteArray[0];

    // Extrahieren der Bytes 2 und 3 (Hash ID)
    uint16_t hashID = (uint16_t)(byteArray[1] << 8) | byteArray[2];

    // Extrahieren der Bytes 4 und 5 (Sender Node)
    uint16_t sender_Node = (uint16_t)(byteArray[3] << 8) | byteArray[4];
    
    // Extrahieren der Bytes 6 bis 9 (Sender IP)
    uint32_t sender_IP;
    memcpy(&sender_IP, byteArray + 5, sizeof(sender_IP));

    // Extrahieren der Bytes 10 und 11 (Sender Port)
    uint16_t sender_Port = (uint16_t)(byteArray[9] << 8) | byteArray[10];
  
    // Umwandlung von sender_IP in einen String
    char ipString[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sender_IP, ipString, INET_ADDRSTRLEN);

    // Umwandlung des Ports in eine Ganzzahl
    int portInt = (int)sender_Port;

    // Erstellen und Initialisieren einer UdpMessage-Struktur
    UdpMessage message = {
        .messageType = message_Type,
        .nodeId = sender_Node,
        .nodeIp = {ipString},
        .nodePort = portInt,
        .hashId = hashID
    };

    // Kopieren der IP-Adresse in die Nachrichtenstruktur
    sprintf(message.nodeIp, "%s", ipString);

    return message;
}




/**
 * Processes an incoming packet from the client.
 *
 * @param conn The socket descriptor representing the connection to the client.
 * @param buffer A pointer to the incoming packet's buffer.
 * @param n The size of the incoming packet.
 *
 * @return Returns the number of bytes processed from the packet.
 *         If the packet is successfully processed and a reply is sent, the return value indicates the number of bytes processed.
 *         If the packet is malformed or an error occurs during processing, the return value is -1.
 *
 */
size_t process_packet(int conn, char* buffer, size_t n) {
    struct request request = {
        .method = NULL,
        .uri = NULL,
        .payload = NULL,
        .payload_length = -1
    };
    ssize_t bytes_processed = parse_request(buffer, n, &request);

    if (bytes_processed > 0) {
        send_reply(conn, &request);

        // Check the "Connection" header in the request to determine if the connection should be kept alive or closed.
        const string connection_header = get_header(&request, "Connection");
        if (connection_header && strcmp(connection_header, "close")) {
            return -1;
        }
    } else if (bytes_processed == -1) {
        // If the request is malformed or an error occurs during processing, send a 400 Bad Request response to the client.
        const string bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(conn, bad_request, strlen(bad_request), 0);
        printf("Received malformed request, terminating connection.\n");
        close(conn);
        return -1;
    }

    return bytes_processed;
}

/**
 * Sets up the connection state for a new socket connection.
 *
 * @param state A pointer to the connection_state structure to be initialized.
 * @param sock The socket descriptor representing the new connection.
 *
 */
static void connection_setup(struct connection_state* state, int sock) {
    // Set the socket descriptor for the new connection in the connection_state structure.
    state->sock = sock;

    // Set the 'end' pointer of the state to the beginning of the buffer.
    state->end = state->buffer;

    // Clear the buffer by filling it with zeros to avoid any stale data.
    memset(state->buffer, 0, HTTP_MAX_SIZE);
}


/**
 * Discards the front of a buffer
 *
 * @param buffer A pointer to the buffer to be modified.
 * @param discard The number of bytes to drop from the front of the buffer.
 * @param keep The number of bytes that should be kept after the discarded bytes.
 *
 * @return Returns a pointer to the first unused byte in the buffer after the discard.
 * @example buffer_discard(ABCDEF0000, 4, 2):
 *          ABCDEF0000 ->  EFCDEF0000 -> EF00000000, returns pointer to first 0.
 */
char* buffer_discard(char* buffer, size_t discard, size_t keep) {
    memmove(buffer, buffer + discard, keep);
    memset(buffer + keep, 0, discard);  // invalidate buffer
    return buffer + keep;
}

/**
 * Handles incoming connections and processes data received over the socket.
 *
 * @param state A pointer to the connection_state structure containing the connection state.
 * @return Returns true if the connection and data processing were successful, false otherwise.
 *         If an error occurs while receiving data from the socket, the function exits the program.
 */
bool handle_connection(struct connection_state* state) {
    // Calculate the pointer to the end of the buffer to avoid buffer overflow
    const char* buffer_end = state->buffer + HTTP_MAX_SIZE;

    // Check if an error occurred while receiving data from the socket
    ssize_t bytes_read = recv(state->sock, state->end, buffer_end - state->end, 0);
    if (bytes_read == -1) {
        perror("recv");
        close(state->sock);
        exit(EXIT_FAILURE);
    } else if (bytes_read == 0) {
        return false;
    }

    char* window_start = state->buffer;
    char* window_end = state->end + bytes_read;

    ssize_t bytes_processed = 0;
    while((bytes_processed = process_packet(state->sock, window_start, window_end - window_start)) > 0) {
        window_start += bytes_processed;
    }
    if (bytes_processed == -1) {
        return false;
    }

    state->end = buffer_discard(state->buffer, window_start - state->buffer, window_end - window_start);
    return true;
}

/**
 * Derives a sockaddr_in structure from the provided host and port information.
 *
 * @param host The host (IP address or hostname) to be resolved into a network address.
 * @param port The port number to be converted into network byte order.
 *
 * @return A sockaddr_in structure representing the network address derived from the host and port.
 */
static struct sockaddr_in derive_sockaddr(const char* host, const char* port) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
    };
    struct addrinfo *result_info;

    // Resolve the host (IP address or hostname) into a list of possible addresses.
    int returncode = getaddrinfo(host, port, &hints, &result_info);
    if (returncode) {
        fprintf(stderr, "Error parsing host/port");
        exit(EXIT_FAILURE);
    }

    // Copy the sockaddr_in structure from the first address in the list
    struct sockaddr_in result = *((struct sockaddr_in*) result_info->ai_addr);

    // Free the allocated memory for the result_info
    freeaddrinfo(result_info);
    return result;
}


/**
 * Sets up a TCP server socket and binds it to the provided sockaddr_in address.
 *
 * @param addr The sockaddr_in structure representing the IP address and port of the server.
 *
 * @return The file descriptor of the created TCP server socket.
 */
static int setup_server_socket(struct sockaddr_in addr) {
    const int enable = 1;
    const int backlog = 1;

    // Create a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Avoid dead lock on connections that are dropped after poll returns but before accept is called
    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1) {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }

    // Set the SO_REUSEADDR socket option to allow reuse of local addresses
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Bind socket to the provided address
    if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Start listening on the socket with maximum backlog of 1 pending connection
    if (listen(sock, backlog)) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return sock;
}


/**
 * Set up a UDP server socket and bind it to the provided sockaddr_in address.
 *
 * @param addr The sockaddr_in structure representing the IP address and port of the server.
 *
 * @return The file descriptor of the created UDP server socket.
 */
static int setup_server_socket_udp(struct sockaddr_in addr) {
    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to the provided address
    if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    return sock;
}


/**
*  The program expects 4; otherwise, it returns EXIT_FAILURE.
*
*  Call as:
*
*  ./build/webserver self.ip self.port
*/
int main(int argc, char** argv) {
    if (argc == 3) {
        // Nur zwei Argumente übergeben, setze peer als pred und succ
        twoNodeDHTInfo.peer.id = (uint16_t)atoi(argv[2]);
        strncpy(twoNodeDHTInfo.peer.ip, argv[1], INET_ADDRSTRLEN);
        twoNodeDHTInfo.peer.port = atoi(argv[2]);

        // Setze peer als pred und succ
        twoNodeDHTInfo.pred = twoNodeDHTInfo.peer;
        twoNodeDHTInfo.succ = twoNodeDHTInfo.peer;
    } else if (argc == 4) {
        // Drei Argumente übergeben, normale Konfiguration
        twoNodeDHTInfo.peer.id = (uint16_t)atoi(argv[3]);
        strncpy(twoNodeDHTInfo.peer.ip, argv[1], INET_ADDRSTRLEN);
        twoNodeDHTInfo.peer.port = atoi(argv[2]);

        // Setzen der Vorgänger-Node-Informationen (PRED)
        twoNodeDHTInfo.pred.id = (uint16_t)atoi(getenv("PRED_ID"));
        strncpy(twoNodeDHTInfo.pred.ip, getenv("PRED_IP"), INET_ADDRSTRLEN);
        twoNodeDHTInfo.pred.port = atoi(getenv("PRED_PORT"));

        // Setzen der Nachfolger-Node-Informationen (SUCC)
        twoNodeDHTInfo.succ.id = (uint16_t)atoi(getenv("SUCC_ID"));
        strncpy(twoNodeDHTInfo.succ.ip, getenv("SUCC_IP"), INET_ADDRSTRLEN);
        twoNodeDHTInfo.succ.port = atoi(getenv("SUCC_PORT"));
    } else {
        // Ungültige Anzahl von Argumenten
        fprintf(stderr, "Usage: %s <IP Address> <Port> [<Node>]\n", argv[0]);
        return EXIT_FAILURE;
    }


    struct sockaddr_in addr = derive_sockaddr(argv[1], argv[2]);

    // Set up a TCP server socket.
    int server_socket = setup_server_socket(addr);

    // Set up a UDP server socket.
    int server_socket_udp = setup_server_socket_udp(addr);

    // Create an array of pollfd structures to monitor sockets.
    struct pollfd sockets[3] = {
        { .fd = server_socket, .events = POLLIN },       // TCP Socket
        { .fd = server_socket_udp, .events = POLLIN }    // UDP Socket
    };

    struct connection_state state = {0};

    while (true) {
        // Warten auf Ereignisse auf den überwachten Sockets
        int ready = poll(sockets, sizeof(sockets) / sizeof(sockets[0]), -1);
        fprintf(stderr, "Hier passiert etwas. ID: %d;;; %d\n", twoNodeDHTInfo.peer.id,sockets[0].revents == POLLIN? 1:0);
        fflush(stderr); 
        if (ready == -1) {
            perror("poll");
            exit(EXIT_FAILURE);
        }
        

        // Verarbeiten der Ereignisse auf den überwachten Sockets
        for (size_t i = 0; i < sizeof(sockets) / sizeof(sockets[0]); i++) {
            if (sockets[i].revents != POLLIN) {
                // Keine POLLIN-Ereignisse auf dem Socket
                continue;
            }

            int s = sockets[i].fd;

            if (s == server_socket) {
                // Ereignis auf dem TCP-Server-Socket
                int connection = accept(server_socket, NULL, NULL);
                if (connection == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    close(server_socket);
                    perror("accept");
                    exit(EXIT_FAILURE);
                } else {
                    connection_setup(&state, connection);
                    
                    // Wechseln zur neuen Verbindung
                    sockets[0].events = 0;
                    sockets[2].fd = connection;
                    sockets[2].events = POLLIN;
                }
            } else if (s == server_socket_udp) {

                fprintf(stderr, "Hier passiert etwas...\n");
                fflush(stderr); 

                // Ereignis auf dem UDP-Server-Socket
                uint8_t buffer[11];
                ssize_t len = recvfrom(server_socket_udp, buffer, sizeof(buffer), 0, NULL, NULL);
                if (len == -1) {
                    perror("recvfrom");
                    exit(EXIT_FAILURE);
                } else if(len == 0){
                    perror("We didnt receive any data..."); 
                    exit(EXIT_FAILURE); 
                }else {
                    fprintf(stderr, "We got a connection\n"); 
                    fflush(stderr); 

                    UdpMessage message = prepare_udp_message(buffer);
                    handle_udp_message(&message);
                }
            } else if (s == state.sock) {
                // Ereignis auf einem verbundenen TCP-Client-Socket
                bool cont = handle_connection(&state);
                if (!cont) {
                    // Bereit für eine neue Verbindung
                    sockets[0].events = POLLIN;
                    sockets[2].fd = -1;
                    sockets[2].events = 0;
                }
            }
        }
    }


    return EXIT_SUCCESS;
}
