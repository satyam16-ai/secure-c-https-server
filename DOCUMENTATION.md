# Secure C HTTPS Server – Documentation

## Overview

This project is a production-grade HTTPS server written in C, designed for performance, security, and extensibility. It supports static file serving, RESTful APIs, WebSocket connections, CGI execution, and HTTP Basic Authentication, all over SSL/TLS. The server is highly configurable via a simple configuration file.

---

## Features

- **HTTPS (SSL/TLS) Support:** Secure communication using OpenSSL.
- **Static File Serving:** Serves files from a configurable directory.
- **REST API Endpoints:** Easily extendable for custom API routes.
- **WebSocket Support:** Real-time, bidirectional communication.
- **CGI Execution:** Runs scripts in the `cgi-bin/` directory.
- **HTTP Basic Authentication:** Protects endpoints with username/password.
- **Configurable:** All major parameters set in `server.conf`.
- **Logging:** Access and error logs for monitoring and debugging.
- **Multi-threaded:** Handles multiple clients concurrently.
- **Customizable:** Modular codebase for easy extension.

---

## Directory Structure

```
https_server/
├── LICENSE
├── Makefile
├── README.md
├── server.conf
├── bin/
│   └── https_server
├── certs/
│   ├── cert.pem
│   └── key.pem
├── cgi-bin/
│   ├── hello.py
│   └── hello.sh
├── include/
│   ├── config.h
│   └── https_server.h
├── logs/
│   ├── access.log
│   └── error.log
├── obj/
│   └── *.o
├── src/
│   ├── config.c
│   ├── logger.c
│   ├── main.c
│   ├── mime.c
│   ├── router.c
│   ├── server.c
│   ├── ssl.c
│   ├── thread_pool.c
│   └── utils.c
├── static/
│   ├── app.js
│   ├── index.html
│   └── style.css
└── tests/
    ├── README.md
    └── test_config.c
```

---

## Configuration (`server.conf`)

Example:

```
# HTTPS Server Configuration
port=8080
cert_file=certs/cert.pem
key_file=certs/key.pem
static_dir=static
log_dir=logs
max_clients=1024
backlog=128
debug=1
auth_user=admin
auth_pass=changeme
```

**Parameters:**

- `port`: Port to listen on (default: 8080).
- `cert_file`, `key_file`: SSL certificate and private key.
- `static_dir`: Directory for static files.
- `log_dir`: Directory for logs.
- `max_clients`: Maximum concurrent clients.
- `backlog`: Listen backlog for socket.
- `debug`: Enable debug logging (1 = on, 0 = off).
- `auth_user`, `auth_pass`: HTTP Basic Auth credentials.

---

## Building

1. **Dependencies:**

   - GCC or Clang
   - OpenSSL development libraries

2. **Build Command:**

   ```sh
   make
   ```

3. **Output:**  
   The server binary will be in `bin/https_server`.

---

## Running

```sh
./bin/https_server server.conf
```

- The server will read configuration from `server.conf`.
- Access the server at `https://localhost:8080` (or your configured port).

---

## Endpoints

- `/`  
  Serves `static/index.html` and other static files.

- `/status`  
  Returns server status (JSON).

- `/api`  
  Example API endpoint (extendable).

- `/ws`  
  WebSocket endpoint.

- `/cgi-bin/hello.py`, `/cgi-bin/hello.sh`  
  Executes CGI scripts and returns output.

---

## Authentication

- HTTP Basic Authentication is enabled for protected endpoints.
- Credentials are set in `server.conf` (`auth_user`, `auth_pass`).

---

## SSL/TLS

- Uses `certs/cert.pem` and `certs/key.pem` for SSL.
- Generate your own certificates for production use:
  ```sh
  openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes
  ```

---

## Logging

- **Access logs:** `logs/access.log`
- **Error logs:** `logs/error.log`
- Log directory is configurable.

---

## Extending the Server

- **Add new routes:**  
  Edit `src/router.c` and update the routing logic.
- **Add new API endpoints:**  
  Implement handler functions in `src/router.c` or new source files.
- **Add new CGI scripts:**  
  Place executable scripts in `cgi-bin/`.

---

## Testing

- Unit tests are in `tests/`.
- Run tests as described in `tests/README.md`.

---

## Security Notes

- Change default credentials before deploying.
- Use strong, unique SSL certificates.
- Run the server as a non-root user in production.

---

## Credits

- Built by [satyam16-ai](https://github.com/satyam16-ai)
- Core design and implementation by the project author.

---

## License

See `LICENSE` for details.

---

## Support

For issues, open a ticket at the [GitHub repository](https://github.com/satyam16-ai/secure-c-https-server).
