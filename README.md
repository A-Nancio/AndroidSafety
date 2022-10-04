# AndroidSafety

A command line application for static code analysis of Android applications through the use of [enjarify](https://github.com/google/enjarify) and [Opal](https://www.opal-project.de/).

## Usage of enjarify
The purpose of enjarify is to perform the conversion of typical android applications (in .apk format) to .jar files which are able to be analyses by the static code analysis tool.

## Usage of Opal
Implemented with Scala, it is the tool that allows the fullfilment of the following tasks by receiving as input a .jar file containing the classes implemented in the android application:

- Listing of all Android APIs being used in the project.
- Scan of the classfiles contained in the .jar file generated  for common vulnerabilities seen in android applications, and present the results on the command line.

# Installation

It is only necessary to install **sbt**, a build tool for scala. It is mandatory to follow the instructions provided in Sbt's official [installation page](https://www.scala-sbt.org/1.x/docs/Setup.html), including installation of dependencies necessary for sbt support.

# Usage
## Enjarify
Instructions of the use of enjarify can be found in detail in its [official repository](https://github.com/google/enjarify) README.md file
## Static Code analysis program
Execution of the static code analysis program can be done in the following way, being `$JARFILEPATH` the path to the jar file to be analysed:
```
> sbt
> compile
> run $JARFILEPATH
```

# State of Development
This project was developed with the goal of matching the capabilities provided by [mobsf](https://mobsf.live/) static code analysis tool. Currently it provided full 

- Out of 36 total analysis provided 

## Code scans currently performed in the project
Code scans are a collection of verifications done in every .class file inside the project to be analysed. A full list implemented by mobsf using regular expressions can be found [here](https://github.com/MobSF/mobsfscan/tree/main/mobsfscan/rules/semgrep):
### General Android

- [x]  Hidden UI
- [x]  Logging
- [ ]  Secrets
- [x]  Word Readable Writable

### Best Practices to follow

- [x]  Android_safety
- [x]  Flag secure
- [x]  Root detection
- [x]  Tapjacking
- [x]  TLS certificate
- [ ]  TLS pinning

### Cryptography

- [x]  ARS ECB
- [ ]  ARS encryption keys
- [x]  CBC padding oracle
- [ ]  CBC static iv
- [x]  insecure random number generator
- [x]  insecure SSL v3
- [x]  RSA no eoap
- [x]  SHA1 hash
- [x]  Weak ciphers
- [x]  Weak hashes
- [ ]  Weak IV
- [ ]  Weak key size

### Deserialization

- [x]  Jackson Deserialization
- [x]  Object Deserialization

### Injection

- [x]  Command injection
- [x]  Formated command injection 
- [x]  SQLite injection

### Network

- [x]  Default HTTP client TLS

### Webview

- [x]  Webview debugging
- [ ]  Webview external storage
- [x]  Webview file access
- [ ]  webview ignore ssl
- [x]  Webview javascript interface

### XXE

- [x]  XMLencoder xxe
- [x]  XMLfactory external entities
- [ ]  XMLfactory xxe

