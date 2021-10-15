#include "agent.h"
#include <grp.h>

void handle_request(int cfd) {
    char *msg = read_message(cfd);
    char *response_msg;

    if (msg == NULL) {
        // TODO: return error reading message

        response_msg = new_proto_msg();
        return;
    } else {
        char *msgtype = (char *)malloc(MSGTYPE_SIZE);
        memcpy(msgtype, msg + CIRCUIT_ID_SIZE, MSGTYPE_SIZE);

        if (strncmp(msgtype, MEMORY_ATTACH, MSGTYPE_SIZE) == 0) {
            response_msg = proto_attach_memory(msg);

        } else if (strncmp(msgtype, MEMORY_DETACH, MSGTYPE_SIZE) == 0) {
            response_msg = proto_detach_memory(msg);

        } else if (strncmp(msgtype, COMPUTE_ATTACH, MSGTYPE_SIZE) == 0) {
            response_msg = proto_attach_compute(msg);

        } else if (strncmp(msgtype, COMPUTE_DETACH, MSGTYPE_SIZE) == 0) {
            response_msg = proto_detach_compute(msg);

        } else {
            log_warn("unknown mode %s\n", msgtype);
            response_msg = set_unknown_mode_response(msg);
            // fill error response
        }
        free(msgtype);
    }

    write_message(cfd, response_msg);
    // error checking

    if (msg != NULL)
        free(msg);
    if (response_msg != NULL)
        free(response_msg);
}

// store a copy of the socket path to unlink on graceful exit
static const char *socket_path = NULL;

void graceful_termination(){
  log_info("Graceful agent termination...\n");

  int errsv = errno;
  int res = remove(socket_path);
  if (res == -1 && errno != ENOENT) {
      log_warn("failed to clean up socket %s: %s \n", socket_path, strerror(errno));
  }
  errno = errsv;

  exit(0);
}

void run_agent(const char* sock_path){

    struct sockaddr_un addr;
    int sfd, cfd;

    if (sock_path == NULL) {
        sock_path = SOCK_PATH;
    }
    log_info("using socket: %s\n", sock_path);

    // avoid exiting when reading on closed pipe, need better handling
    signal(SIGPIPE, SIG_IGN);

    // graceful exit on TERM, INT
    signal(SIGTERM, graceful_termination);
    signal(SIGINT,  graceful_termination);

    // produce a sockaddr_un struct for the given socket path
    memset(&addr, 0, sizeof(addr.sun_path) - 1);

    addr.sun_family = AF_UNIX; // use unix socket

    // caution: this silently trucates the length of the socket path to
    //          sizeof(addr.sun_path), which is usually 108 characters.
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    // to make the truncation explicit and visible in the log, write the
    // new socket path again here.
    log_info("starting server with sock_path: %s\n", addr.sun_path);

    // store a copy of the socket path to unlink the socket on graceful exit
    socket_path = strdup(addr.sun_path);
    if (socket_path == NULL) {
        log_error("error creating socket: %s\n", strerror(errno));
        exit(1);
    }

    sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd == -1) {
        log_error("error creating socket: %s\n", strerror(errno));
        exit(1);
    }

    // attempt to remove a stale socket from previous runs.
    // it's ok if this fails, because we catch the error again in the call to bind()
    int errsv = errno;
    int res = remove(socket_path);
    if (res == -1 && errno != ENOENT) {
        log_warn("failed to remove stale socket %s: %s\n", socket_path, strerror(errno));
    }
    errno = errsv;

    // prepare the socket for receiving connections
    res = bind(sfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    if (res == -1) {
        log_error("error while binding the socket: %s\n", strerror(errno));
        exit(2);
    }

    res = listen(sfd, BACKLOG);
    if (res == -1) {
        log_error("error listening on bound socket: %s\n", strerror(errno));
        exit(3);
    }

    // set the socket permissions
    // first, determine the group id of the socket group (defaults to 'ocxl')
    errsv = errno;
    struct group *ocxl = getgrnam(SOCK_GRP);
    if (ocxl == NULL) {
        log_warn("group '%s' not found - unable to set socket permissions: %s\n", SOCK_GRP, strerror(errno));
    }
    errno = errsv;

    // second, change group ownership to the correct group id
    // note: use chown instead of fchown here, since fchown does not
    //       work on file descriptors produced by socket()
    if (ocxl != NULL) {
        errsv = errno;
        res = chown(socket_path, -1, ocxl->gr_gid);
        if (res == -1) {
            log_warn("failed to set group ownership on socket: %s\n", strerror(errno));
        }
        errno = errsv;
    }

    // third, determine rwx perms for the socket, add add read/write
    // permissions for the group, and chmod
    struct stat sock_stat;
    mode_t sock_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; // 0x644
    errsv = errno;
    res = stat(socket_path, &sock_stat);
    if (res == -1) {
        log_warn("unable to determine current socket permissions. assuming 0x644: %s\n", strerror(errno));
    } else {
        sock_mode = sock_stat.st_mode;
    }
    errno = errsv;
    sock_mode |= S_IWGRP | S_IRGRP;

    errsv = errno;
    res = chmod(socket_path, sock_mode);
    if (res == -1) {
        log_warn("unable to change socket permissions: %s\n", strerror(errno));
    }
    errno = errsv;

    // start the server event loop
    log_info("Starting thymesisflow server...\n");

    for (;;) {
        log_info("Ready to accept new requests...\n");

        cfd = accept(sfd, NULL, NULL);
        if (cfd == -1) {
            log_info("error during accept: %s\n", strerror(errno));
            exit(4);
        }
        handle_request(cfd);

        log_info("closing connection...\n");

        errsv = errno;
        res = close(cfd);
        if (res == -1) {
            log_error("error during close: %s\n", strerror(errno));
            // don't exit here, we might return to a serviceable state on the next
            // call to accept(). if not, we can always fail there.
        }
        errno = errsv;
    }
}
