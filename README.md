# a http client for windows

nhttp is a simple http/https client for Windows, written in C++17 and using nothing but the WIN32 API.

## Usage

`nhttp [link]`

## Features

### - TLS support

Can send and receive from both unsecured and secured websites with no difficulty

### - Multithreaded content download

Automatically downloads all the necessary files to properly render a page for most websites

### - Redirect handling

Will recursively follow redirects when directed

## Currently implemented
- HTTP/1.1
- Non-blocking sockets and handling
- GET requests
- Redirect Handling
- Error handling and retries if webpage fails

## Planned
- POST requests
