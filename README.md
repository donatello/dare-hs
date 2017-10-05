# Haskell implementation of the Data At Rest Encryption (DARE) format

## Links

Format specification: https://github.com/minio/sio/blob/master/DARE.md

Reference Go implementation and tool: https://github.com/minio/sio

This implementation is intended to be interoperable with the Go
implementation - this means:

1. Given the same keys and encryption parameters, both implementations
   will generate identical encrypted output, and
2. Data encrypted with the `ncrypt` tool written in Golang, can be
   decrypted with the `dare-hs-exe` tool produced by compiling the
   present project, and vice versa.
