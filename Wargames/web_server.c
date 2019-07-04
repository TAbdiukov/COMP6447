#define LIST_PAGES 0x51
#define READ_PAGE  0x52
#define WRITE_PAGE 0x53
#define COMMAND    0x54

#define FILENOTAVAIL "\x69\x01 FILE NOT AVAILABLE!"
#define BEGINFILE    "\x68\x01 BEGIN FILE: END WITH '!!!'"
#define ARTICLEWROTE "\x68\x02 ARTICLE HAS BEEN WRITTEN!"
#define READY        "\x68\x03 READY!"

int write_socket(int socket, char* buf, ssize_t len) {
    ssize_t byteswrote = 0;
    ssize_t ret = 0;

    while (byteswrote < len) {
        ret = send(socket, buf+byteswrote, len-byteswrote, 0);

        if (ret < 0) {
            return -1;
        }   
        
        if (ret == 0) {
            break;
        }

        byteswrote += ret;
    }

    return byteswrote;
}

int read_socket(int socket, char *buf, ssize_t len) {
    ssize_t ret = 0;
    ssize_t bytesread = 0;

    while (bytesread < len) {
        ret = recv(socket, buf+bytesread, len - bytesread, 0);
        
        if (ret < 0) {
            return -1;
        }

        if (ret == 0) {
            break;
        }

        bytesread += ret;
    }

    return bytesread;
}   

void logit(char* fmt, ...) {
    char buffer[4096];
	va_list arguments;
	va_start(arguments, fmt);
	vsnprintf(buffer, sizeof(buffer)-1, fmt, arguments);
	va_end(arguments);
    syslog(10, buffer);
}

void write_page(int socket, char *action) {
    FILE *file;
    char buf[1024];
    char path[1024];
    
    ssize_t x, y;
    int complete = 0;

    strcpy(path, "./webpath/");

    strncat(path, &action[1], sizeof(path));
    
    logit("Writing stuff %s: ", path);

    file = fopen(&action[1], "w");

    if (!file) {
        write_socket(socket, FILENOTAVAIL, sizeof(FILENOTAVAIL));
        return;
    }

    write_socket(socket, BEGINFILE, sizeof(BEGINFILE));

    while (1) {
        memset(buf, 0, sizeof(buf));
        x = read_socket(socket, buf, sizeof(buf) - 1);
        
        for(int i = 0; i < x; i++) {
            if (buf[i] == '!') {
                if (buf[i+1] == '!' && buf[i+2] == '!') {
                    buf[i] = 0x0;
                    complete = 1;
                }
            }
        }
        fputs(buf, file);
        if (complete) {
            break;
        }
    }
    write_socket(socket, ARTICLEWROTE, sizeof(ARTICLEWROTE));
    fclose(file);

}


void read_page(int socket, char *action) {
    FILE *file;
    char buf[100];
    char path[100];

    logit(&action[1]);
    
    strcpy(path, "./webpath/") ;
    strcat(path, &action[1]);

    logit("Reading %s", path);

    file = fopen(path, "r");

    if(!file) {
        write_socket(socket, FILENOTAVAIL, sizeof(FILENOTAVAIL));
        return;
    }

    while (fgets(buf, 1000, file)) {
        write_socket(socket, buf, strlen(buf));
    }
    fclose(file);
}

void list_pages(int socket, char* action) {
    FILE *list;
    char buf[100];
    logit("User has requesed a list of pages");

    memset(buf, 0, sizeof(buf));
    system("ls ./webpath/ > list.txt");
    list = fopen("list.txt", "r");
    while(fgets(buf, sizeof(buf) - 1, list)) {
        write_socket(socket, buf, strlen(buf));
    }
    fclose(list);
}

void command(int socket, char* action) {
    logit("Executing %s", &action[1]);
    system(&action[1]);
}

int handle_conn(int socket) {
    char action[1024];
    ssize_t len;

    while (1) {
        write_socket(socket, READY, sizeof(READY)); 
        memset(action, 0, sizeof(action));
        len = read_socket(socket, action, sizeof(action));
        int admin_enabled = 0;

        switch (action[0]) {
            case LIST_PAGES:
                list_pages(socket, action);
                break;
            case READ_PAGE:
                read_page(socket, action);
                break;
            case WRITE_PAGE:
                write_page(socket, action);
                break;
            case COMMAND:
                if (!admin_enabled) {
                    logit("Command received but not admin, ignoring command");
                }
                command(socket, action);
            default:
                logit("Unknown action %x", action[0]);
        }
    }
}

int setup_networking(unsigned short port) {
    int sock = 0;
    struct sockaddr_in sin;

    memset(&sin, 0, sizeof(sin));

    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) 
        return -1;

    int opt = 1;

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(sock, (struct sockaddr *) &sin, sizeof(sin));
    listen(sock, 10);

    return sock;
}

void run_server(int socket) {
    int fd = 0;
    struct sockaddr_in client;
    socklen_t len = 0;

    memset((char*)&client, 0, sizeof(client));

    while (1) {
        fd = accept(socket, (struct sockaddr *) &client, &len);
        if (fork() == 0) {
            handle_conn(fd);
            close(fd);
            exit(0);
        }
    }   
}

int main() {
    int sock;
    
    sock = setup_networking(9447);
    logit("Setup networking");

    run_server(sock); 

    exit(0);
}
