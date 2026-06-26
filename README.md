# osnmalib

`osnmalib` is a self-contained C++ library for decoding and authenticating Galileo Open Service Navigation Message Authentication (OSNMA) data.

The library processes decoded Galileo E1-B I/NAV pages and performs:

* OSNMA page and subframe assembly
* DSM-PKR and Merkle-tree verification
* DSM-KROOT signature verification
* TESLA key-chain verification
* MACK parsing and tag verification
* ADKD 0, ADKD 4 and ADKD 12 processing
* Galileo ephemeris, ionosphere and time-parameter decoding
* authenticated navigation-data output
* diagnostic logging

## Requirements

* C++20 compiler (Visual Studio 2022-143 project included)
* 32-bit or 64-bit build
* No external binary dependencies

The required subset of mbed TLS is included under:

```text
third_party/mbedtls
```

All library sources and embedded cryptographic sources must be compiled using the same architecture and runtime-library configuration as the calling application.

## Input

The main input interface accepts decoded Galileo I/NAV page parts:

```cpp
OsnmaAuthenticator::FeedRawInavPage(...)
```

The input page timestamp must correspond to the transmission time of the first bit of the complete two-second I/NAV page.

The current combined input path expects Galileo **E1-B I/NAV**, because the OSNMA reserved field is carried by E1-B.

Receiver-specific formats, such as Septentrio `GALRawINAV`, should be converted by an external adapter before being passed to the library.

## Output

The library can produce Pegasus-compatible semicolon-separated files:

```text
.eph
.iono
.dtime
.osnmalog
```

The navigation files contain both initially decoded and subsequently authenticated navigation objects.

Important time fields are:

* `TX_WEEK` / `TX_TOM`: first-bit transmission epoch of the navigation data
* `RX_WEEK` / `RX_TOM`: complete-page availability epoch
* `AUTH_WEEK` / `AUTH_TOM`: epoch at which authentication became available

Galileo satellite identifiers in the Pegasus CSV output use the SVID range `71..106`.

## Testing

The repository contains self-tests covering the main OSNMA processing components.

Official Galileo OSNMA test vectors can be processed using the test-vector reader and compared with the expected authentication results.

## Status

The library has been tested with:

* official Galileo OSNMA test vectors
* live Galileo data recorded by Septentrio receivers
* independent results produced by the European Commission Joint Research Centre

The project remains under development and should not be considered certified for safety-critical use.

## License

The original osnmalib source code is licensed under the Apache License,
Version 2.0. See [LICENSE](LICENSE).

This repository includes a reduced source subset of Mbed TLS 3.6.6,
used under the Apache License 2.0 option of its dual licence.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
[third_party/mbedtls/LICENSE](third_party/mbedtls/LICENSE) for details.

