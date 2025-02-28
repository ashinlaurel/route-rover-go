# Route Rover Go - Tests

This directory contains unit tests for the Route Rover Go application.

## Structure

- `controllers/`: Tests for controller functions
  - `auth_controller_test.go`: Tests for authentication controller functions (login, profile, update)
- `middlewares/`: Tests for middleware functions
  - `auth_test.go`: Tests for authentication middleware (token generation, validation, etc.)

## Test Approach

The tests use a combination of approaches:

1. **Controller Tests**: These tests use a simplified approach where we create mock handlers that simulate the behavior of the real controllers. This allows us to test the logic without needing to connect to a real database.

2. **Middleware Tests**: These tests directly test the middleware functions, ensuring they correctly handle authentication tokens and user authorization.

## Running Tests

To run all tests:

```bash
go test ./tests/...
```

To run tests for a specific package:

```bash
go test ./tests/controllers
go test ./tests/middlewares
```

To run a specific test:

```bash
go test ./tests/controllers -run TestLoginUser
go test ./tests/middlewares -run TestAuthMiddleware
```

To run tests with verbose output:

```bash
go test -v ./tests/...
```

## Test Coverage

To generate test coverage:

```bash
go test ./tests/... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Dependencies

The tests use the following libraries:
- Go's built-in testing framework
- github.com/stretchr/testify/assert for assertions
- github.com/gofiber/fiber/v2 for HTTP testing

Make sure these dependencies are installed:

```bash
go get github.com/stretchr/testify
go get github.com/gofiber/fiber/v2
``` 