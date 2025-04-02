# LoadThatPE

![LoadThatPE](.assets/loadthatpe_demo.png)

> A simple PE Loader tool that loads a PE from memory, decrypt it, resolve its imports, relocate its sections, and redefine its entry point to execute seamlessly from memory.

## 🚀 Features

- **In-memory decryption**: Decrypts and loads PE files directly from memory.
- **Imports resolution**: Dynamically resolves imports even for complex executables.
- **Section relocation**: Updates section locations based on adjusted memory offsets.
- **Flexible entry point redirection**: Executes the PE with its redefined entry point.
 
> **⚠️ Disclaimer:**  
This tool is strictly for **educational and research purposes**. Misuse of this tool for malicious or unauthorized activities is strictly prohibited. Respect the laws and ethical guidelines of your jurisdiction.

---

## 🛠️ Installation

### Prerequisites
Make sure you have the following installed:

- `Windows` operating system (recommended for PE file handling).
- `Visual Studio` or `GCC` for compiling the project.
- `C/C++` compiler for maximum performance.

### Clone the Repository

```bash
git clone https://github.com/ProcessusT/LoadThatPE.git
cd LoadThatPE
