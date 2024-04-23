# Shellcode Execution

This Python script focuses on process creation and direct shellcode execution within a newly started process, using ctypes to interface with the Windows API. This method differs from DLL injection by inserting and running raw shellcode in the process's memory, offering a more direct approach to executing arbitrary code. This technique is powerful and can be used for various purposes, including testing, debugging, and security research.

## Disclaimer

The tools and scripts provided in this repository are made available for educational purposes only and are intended to be used for testing and protecting systems with the consent of the owners. The author does not take any responsibility for the misuse of these tools. It is the end user's responsibility to obey all applicable local, state, national, and international laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Under no circumstances should this tool be used for malicious purposes. The author of this tool advocates for the responsible and ethical use of security tools. Please use this tool responsibly and ethically, ensuring that you have proper authorization before engaging any system with the techniques demonstrated by this project.

## Prerequisites

- **Operating System**: Tested on Windows, version 10 22H2.
- **Python Version**: Python 3.6+
- **User Permissions**: Administrative privileges are required to execute the script due to the nature of its operations, which involve process and memory manipulation.
- **Metasploit Framework**: `msfvenom` is used for generating the shellcode.

## Installation

1. **Python Environment Setup**: Ensure Python and pip are installed. Install the required libraries using:
    
    ```bash
    pip install ctypes
    ```
    
2. **Download Scripts**: Clone or download the scripts from the project repository to your local machine.

## Usage

### Shellcode Setup (Metasploit Framework)

To create shellcode using the Metasploit Framework, you'll be using `msfvenom`. `msfvenom`is a command-line instance of Metasploit that is used for generating shellcode for various payloads or for encoding payloads to help evade detection. You can use this shellcode in your Python scripts for process injection and execution testing.

1. **Generate Shellcode with msfvenom:**
    - Execute the `msfvenom` command in Metasploit Framework to generate shellcode for a MessageBox payload.
        
        ```bash
        msfvenom -a x64 --platform windows -p windows/x64/messagebox TITLE="Test Message" TEXT="Shellcode Execution: Success!" -f python
        ```
        
        - `-a x64`: Specifies the architecture for the payload. In this case, `x64` for 64-bit.
        - `--platform windows`: Specifies the target platform.
        - `-p windows/x64/messagebox`: Specifies the payload to use, which is a MessageBox for 64-bit Windows.
        - `TITLE="Test Message"`: Sets the title of the MessageBox.
        - `TEXT="Shellcode Execution: Success!"`: Sets the text of the MessageBox.
        - `-f python`: Specifies the output format. In this case, `python`, meaning the shellcode will be formatted as a Python variable.
2. **Use the Generated Shellcode:**
    - `msfvenom` will generate the shellcode and output it in the format specified. For the `-f python`option, the output will be a Python script snippet that includes the shellcode as a byte array, which you can then use in your injection and execution testing.
    - The output will look something like this (this is an example, your actual output will vary):
        
        ```bash
        buf =  b""
        buf += b"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00"
        buf += b"\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65"
        buf += b"\x48\x8b\x52\x60\x3e\x48\x8b\x52\x18\x3e\x48\x8b"
        buf += b"\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48\x0f\xb7\x4a"
        buf += b"\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
        buf += b"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52"
        buf += b"\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
        buf += b"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
        buf += b"\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44"
        buf += b"\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
        buf += b"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31"
        buf += b"\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75"
        buf += b"\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd6"
        buf += b"\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
        buf += b"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
        buf += b"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e"
        buf += b"\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20"
        buf += b"\x41\x52\xff\xe0\x58\x41\x59\x5a\x3e\x48\x8b\x12"
        buf += b"\xe9\x49\xff\xff\xff\x5d\x3e\x48\x8d\x8d\x39\x01"
        buf += b"\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5\x49\xc7"
        buf += b"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
        buf += b"\x00\x3e\x4c\x8d\x85\x2c\x01\x00\x00\x48\x31\xc9"
        buf += b"\x41\xba\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41"
        buf += b"\xba\xf0\xb5\xa2\x56\xff\xd5\x53\x68\x65\x6c\x6c"
        buf += b"\x63\x6f\x64\x65\x20\x45\x78\x65\x63\x75\x74\x69"
        buf += b"\x6f\x6e\x3a\x20\x53\x75\x63\x63\x65\x73\x73\x21"
        buf += b"\x00\x54\x65\x73\x74\x20\x4d\x65\x73\x73\x61\x67"
        buf += b"\x65\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c"
        buf += b"\x00"
        ```
        
    - To test the shellcode, you'll need to modify the Python script to inject this shellcode into a process on your Windows test environment.

### Python Script

1. **Configure the Python Script**: Integrate the generated shellcode into the Python script in the designated shellcode buffer `buf`.
2. **Run the Script**: Run the script and follow the on-screen prompts to enter the target process ID (PID).
    
    ```bash
    python3 shellcode_execution.py
    ```
## How It Works

- **Setting Up Constants and Structures:** The script begins by defining necessary ctypes and Windows API constants (e.g., access rights, memory allocation types) and structures (`SECURITY_ATTRIBUTES`, `STARTUPINFO`, `PROCESS_INFORMATION`). These constants and structures are essential for interacting with the Windows API functions used later in the script.
- **Process Creation:** A new process (`notepad.exe`) is created in a suspended state using `CreateProcessA`. This is done to ensure that the shellcode can be injected and set up before the process begins executing its own code. The process is created without a window to keep the operation discreet.
- **Memory Allocation for Shellcode:** Memory within the newly created process is allocated using `VirtualAllocEx`. This allocated memory is set with `PAGE_READWRITE` permissions initially, to allow writing the shellcode into it.
- **Writing Shellcode into Allocated Memory:** The shellcode (`buf`) is written into the allocated memory using `WriteProcessMemory`. This function copies the shellcode from the script's memory space into the target process's allocated memory space.
- **Changing Memory Protection:** The protection on the memory where the shellcode is written is changed from `PAGE_READWRITE` to `PAGE_EXECUTE_READ` using `VirtualProtectEx`. This step is necessary to execute the shellcode, as memory must be executable.
- **Queueing an Asynchronous Procedure Call (APC):** An APC is queued to the main thread of the suspended process using `QueueUserAPC`. The APC points to the start of the shellcode in the target process's memory. When the thread resumes, it will execute the shellcode as part of its normal operation.
- **Resuming the Thread:** The main thread of the process is resumed with `ResumeThread`, allowing the process to start executing. The queued APC ensures that the shellcode is executed immediately upon resumption.

## Output Example

```bash
Started process: Handle:300, PID:5360, TID:4836
Remote Memory Allocated at: 0x1e7d2030000
Shellcode Written: 337 bytes
Memory protection changed from 4 to 32
APC queued to thread ID: 4836
Thread resumed: ID: 4836
```

![App Memory Address](/images/app_memory_address.png)

![App TID](/images/app_threads.png)

![Shellcode Message](/images/shell_execution_success.png)

## Contributing

If you have an idea for an improvement or if you're interested in collaborating, you are welcome to contribute. Please feel free to open an issue or submit a pull request.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.
