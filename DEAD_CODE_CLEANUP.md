# Dead-code cleanup

This source package includes the embedded Mbed TLS 3.6.6 subset and removes
code that was confirmed unused by the OSNMA library and its test executable.

Removed:

- obsolete `osnma_dsm_parser.*`;
- unused pending-MACK verification implementation;
- unused private navigation and MAC-input helpers;
- unused `AuthRecord` result payload;
- legacy standalone ephemeris/ionosphere/time queues;
- unused public SHA-512 wrapper and Mbed TLS 2 compatibility branches;
- nested historical source ZIPs, Visual Studio `.user` files, and generated
  `x64` build output.

The backward-compatible `ProcessSubframe` overload and useful public
`OsnmaAuthenticator` APIs are retained.
