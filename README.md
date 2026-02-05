# The Bouncy Castle Crypto Package For Java

> [!WARNING]
> This package is in ALPHA. 
> Therefore, it should not be considered production-ready, and it will be evolving rapidly over the coming months.


The Bouncy Castle Crypto package is a Rust implementation of cryptographic algorithms, it was developed by the Legion of the Bouncy Castle, a registered Australian Charity, with a little help! The Legion, and the latest goings on with this package, can be found at https://www.bouncycastle.org.

The aim of this package is to bring the Bouncy Castle team's experience building easy-to-use and FIPS-validated cryptography to Rust. The build system is designed so that you can build the entire library, a single algorithm, or anything you need. It also comes with a command-line.

This package is currently in ALPHA, meaning that it is not complete or production-ready yet. We are releasing only a small set of cryptographic algorithms in order to get feedback from the community on the API and build structure.

If you are interested in purchasing a support contract or accelerating the development of this package, please contact us at [office@bouncycastle.org](mailto:office@bouncycastle.org) or [mike@bouncycastle.org](mailto:mike@bouncycastle.org).

## Building

This project is structured as a cargo workspace with each cryptographic algorithm segmented into a sub-crate.

You can build the main library and the `bc-rust` command-line utility with:

```
cargo build
```

Or you can build a single sub-crate by name, for example:

```
cargo build -p sha3
```

... or any other cargo magic that you wish :)

## Legal

Except where otherwise stated, this software is distributed under a license based on the MIT X Consortium license. To view the license, [see here](https://www.bouncycastle.org/licence.html). The OpenPGP library also includes a modified BZIP2 library which is licensed under the [Apache Software License, Version 2.0](https://www.apache.org/licenses/). 
