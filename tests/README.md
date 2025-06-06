# Tests for HTTPS Server

This directory contains unit and integration tests for the HTTPS server project.

## Running Tests

1. Install the Check unit testing framework:
   ```sh
   sudo apt-get install check
   ```
2. Build the tests:
   ```sh
   make test
   ```
3. Run the tests:
   ```sh
   ./bin/tests
   ```

## Test Coverage
- Config file parsing
- Utility functions
- (Planned) HTTP request/response handling
- (Planned) Integration tests for server startup and basic requests 