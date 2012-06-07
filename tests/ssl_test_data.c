#include "stdinc.h"
#include "ssl_test_data.h"

#define SERVER_KEY_FILE "./ssl-test-data/sslcap-test-key.pem"
const char* server_keyfile = SERVER_KEY_FILE;

#define SERVER2_KEY_FILE "./ssl-test-data/server2.key"

#ifdef _WIN32
SSL_ServerParams SSL_ServerParam2 = { {192,168,1,102}, 443, SERVER2_KEY_FILE, "server2" };
SSL_ServerParams SSL_ServerParam3 = { {192,168,1,100}, 443, SERVER_KEY_FILE, "" };

#elif defined(__linux) || defined(__FreeBSD__) || defined(__APPLE__)
SSL_ServerParams SSL_ServerParam2 = { {MAKE_IP(192,168,1,102)}, 443, SERVER2_KEY_FILE, "server2" };
SSL_ServerParams SSL_ServerParam3 = { {MAKE_IP(192,168,1,100)}, 443, SERVER_KEY_FILE, "" };
#endif
