# Production-Grade HTTPS Server in C

A high-performance, secure HTTPS server written in C, featuring static file hosting, authentication, CGI support, logging, and extensible routing. Ideal for learning, prototyping, or as a foundation for custom secure web services.

---

## 🚀 Features

- **HTTPS Static File Hosting**: Serves files from the `static/` directory over TLS 1.2+.
- **HTTP Basic Authentication**: All static content is protected by username/password.
- **Configurable Endpoints**:
  - `/status`: JSON server status.
  - `/api`: API stub (ready for extension).
  - `/ws`: WebSocket demo endpoint.
  - `/cgi-bin/`: Run CGI scripts (e.g., Python, Bash).
- **Security**:
  - TLS 1.2+ enforced (self-signed certs by default).
  - Secure HTTP headers (HSTS, X-Frame-Options, etc.).
  - Directory traversal protection.
- **Logging**: Access and error logs in `logs/`.
- **Concurrency**: Event-driven I/O with thread pool support.
- **Custom Routing**: Easily extend with new endpoints.
- **Command-Line Configuration**: Set port, directories, certs, and more.

---

## 📁 Project Structure

```
https_server/
├── src/              # Source files (main, server, SSL, router, etc.)
├── include/          # Header files
├── static/           # Static website files (index.html, style.css, app.js, ...)
├── cgi-bin/          # CGI scripts (hello.py, hello.sh, ...)
├── certs/            # SSL certificate and key
├── logs/             # Access and error logs
├── bin/              # Compiled server binary
├── Makefile          # Build configuration
├── README.md         # This file
└── ...
```

---

## 🛠️ Building

### Prerequisites

- GCC or Clang
- OpenSSL development libraries
- Make
- pthreads

### Install dependencies (Ubuntu/Debian):

```sh
sudo apt-get install build-essential libssl-dev
```

### Build the server:

```sh
cd https_server
make
```

---

## 🔧 Configuration & Usage

### Command-Line Options

```
./bin/https_server [options]

Options:
  -p, --port PORT       Specify server port (default: 8080)
  -d, --dir DIR         Set static files directory (default: static)
  -l, --log LOG_DIR     Set log directory (default: logs)
  -c, --cert CERT_FILE  SSL certificate file (default: certs/cert.pem)
  -k, --key KEY_FILE    SSL private key file (default: certs/key.pem)
  -D, --debug           Enable debug mode
  -h, --help            Show this help message
```

### Example: Start the server

```sh
./bin/https_server -D
```

---

## 🔒 Authentication

- All static files require HTTP Basic Auth.
- Default credentials: `admin` / `changeme` (see config).
- Change credentials in the config or code for production use.

---

## 🌐 Endpoints & Features

- `/` — Serves `static/index.html` (and other static files).
- `/status` — Returns JSON status: `{ "status": "running", "uptime": 0 }`
- `/api` — API stub (returns 501 Not Implemented)
- `/ws` — WebSocket demo endpoint (plain text response)
- `/cgi-bin/hello.py` — Runs CGI script and returns output

---

## 📝 Logging

- Access logs: `logs/access.log`
- Error logs: `logs/error.log`
- Includes all requests, authentication attempts, errors, and CGI runs.

---

## 🧩 Extending the Server

- Add new endpoints in `src/router.c`.
- Add new static files to `static/`.
- Add new CGI scripts to `cgi-bin/` (make them executable).
- Update authentication logic or add new auth methods as needed.

---

## ⚠️ Security Notes

- For production, use a valid SSL certificate (not self-signed).
- Change default credentials.
- Review and harden CGI scripts.
- Regularly audit code and dependencies.

---

## 🤝 Contributing

Contributions are welcome! Please open issues or pull requests for improvements, bug fixes, or new features.

---

## 📝 License

MIT License. See LICENSE for details.

---

© 2025 Satyam Tiwari. All rights reserved.  
Created by Satyam Tiwari
