Introduction
--------------
niceapi is the [NICE 1.1](https://www.nicealliance.org/specs/) compliant library that provides functions:
- NICE Deivice
    - Send NICE API Request
    - Receive NICE API Response and parse
    - Create SceneMark And SceneData
    - Encryption of SceneMark and SceneData
- NICE Server
    - Parse NICE API Request
    - Create NICE API Response
    - Decryption of SceneMark and SceneData
- NICE Security
    - JWS Signing and Verification
    - JWE Encryption and Decryption

License
--------------
The source code is licensed under the BSD 3-clause license.

Dependencies
--------------
- Python (>= 3.8.0)
- pip (>= 21.3.1)
- build (>= 0.7.0)
- requests (>= 2.28.0)
- authlib (>= 1.0.1)
- cryptography (>= 37.0.2)
- pycryptodomex (>= 3.15.0)

Build
--------------
wheel and sdist format files of niceapi are generated into `dist/`.
``` sh
make build
```

Install
--------------
- Install by manual
``` sh
pip install niceapi
```
- Install by the sdist format file
``` sh
pip install niceapi-1.0.0.tar.gz
```
- Install by the wheel format file
``` sh
pip install niceapi-1.0.0-py3-none-any.whl
```
- Install by pypi
``` sh
Not supported yet
```

Documents
--------------
Documents are generated into `docs/build`.
``` sh
make docs
```

Test
--------------
The test results are generated into `tests/`.
``` sh
make test
```

Lint
--------------
The Linting results are displayed in the terminal.
``` sh
make lint
```

Format code style
--------------
Automatically format niceapi code.
``` sh
make format
```

