# Signature Extractor Utility

The Signature Extractor Utility is a command-line tool designed to work with Mach-O, Dmg, and PE file formats. It can both extract a signature from a signed application and apply an existing signature to an application.

## Features

- **Extract Signature**: Retrieve the signature information from a signed application and save it as a JSON file.
- **Apply Signature**: Apply a previously extracted signature to an application. If the application is already signed, the existing signature will be replaced.

## Command-Line Interface

The tool provides two main commands:

### 1. `extract`

Extracts the signature from the specified input file and saves it to an output file.

**Parameters:**

- `--input` or `-i` (string, required):
  Path to the signed application whose signature needs to be exported.

- `--output` or `-o` (string, required):
  Path where the extracted signature will be saved.

**Example:**

```bash
SignatureExtractor extract --input "/path/to/signed/app" --output "/path/to/signature.json"
```

### 2. `apply`

Applies a previously extracted signature to an input file and saves the result to an output file. If the file is already signed, the signature will be replaced.

**Parameters:**

- `--input` or `-i` (string, required):
  Path to the application where the signature should be applied.

- `--signature` or `-s` (string, required):
  Path to the file containing the signature.

- `--output` or `-o` (string, required):
  Path to save the result, which is the application with the applied signature.

- `--skip-verification` (boolean, optional):
  Flag to skip signature verification. If set, only the technical feasibility of signature transposition will be checked. By default, verification is performed.

**Example:**

```bash
SignatureExtractor apply --input "/path/to/application" --signature "/path/to/signature.json" --output "/path/to/resulting/application"
```

If you want to skip validation of resulting binary:

```bash
SignatureExtractor apply -i "/path/to/application" -s "/path/to/signature.json" -o "/path/to/resulting/application" --skip-verification
```

## Result code

The program exits with code 0 if the operation was successful. A non-zero exit code indicates problems.

