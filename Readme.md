# File Protection System

## Overview

The File Protection System is a robust C-based application designed to safeguard files within a specified directory. It employs file system monitoring and access control mechanisms to prevent unauthorized modifications, deletions, or moves of protected files.

## Features

- Real-time file system monitoring
- Protection against file modifications, deletions, and moves
- Template-based file protection
- Password-protected system control
- Logging of all protection events and system activities
- User-friendly command-line interface

## Requirements

- Linux-based operating system
- GCC compiler
- Make build system
- libcrypt development libraries

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/file-protection-system.git
   cd file-protection-system
   ```

2. Run the installation script to set up dependencies:
   ```
   sudo chmod +x install_dependencies.sh
   sudo ./install_dependencies.sh
   ```

3. Compile the project:
   ```
   make
   ```

4. The executable will be installed in `/bin/file_protection`

## Configuration

1. Edit the `template.tbl` file:
   - First line: Hashed password for system control (initially set to "password")
   - Second line: Absolute path to the directory you want to protect
   - Subsequent lines: File patterns to protect (e.g., *.txt, *.doc)

Example `template.tbl`:
```
018RdQ7SlKKLA
/home/user/protected_directory
*
*.txt
*.doc
*.docx
*.pdf
```

## Usage

Run the application with root privileges:

```
sudo /bin/file_protection
```

### Available Commands

- `help`: Display available commands
- `enable`: Enable file protection
- `disable`: Disable file protection (requires password)
- `change`: Change the system password
- `status`: Show current protection status
- `stop`: Exit the program

## How It Works

1. The system monitors the specified directory using inotify.
2. When a file event occurs, it checks if the file matches any protected patterns.
3. For protected files, it prevents modifications by:
   - Setting the immutable flag
   - Changing permissions to read-only
   - Blocking creation, deletion, and move operations

## File Structure

- `main.c`: Entry point of the application
- `file_protection.h`: Header file with function declarations and includes
- `file_operations.c`: File-related operations and event handling
- `user_interface.c`: User interaction and command processing
- `system_initialization.c`: System setup and main loop
- `Makefile`: Compilation and installation instructions
- `install_dependencies.sh`: Script to install required dependencies
- `template.tbl`: Configuration file for protected directory and file patterns

## Logging

The system logs all activities to `file_protection.log` in the same directory as the executable. This includes:

- System initialization and shutdown
- Protection enabling/disabling
- File events (create, delete, modify, move)
- User authentication attempts
- Password changes

## Security Considerations

- The system requires root privileges to set file attributes and permissions.
- The password is stored as a hash in the `template.tbl` file.
- Ensure that the `template.tbl` file has restricted read/write permissions.

## Limitations

- The system currently only protects files in a single directory (not recursive).
- It does not prevent reading of protected files, only modifications.
- Root users can still modify protected files (as the application runs with root privileges).

## Contributing

Contributions to improve the File Protection System are welcome. Please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/improvement`)
3. Make your changes and commit them (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Linux inotify mechanism for file system monitoring
- libcrypt for password hashing
