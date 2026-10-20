# Installation
## Requirements
- Linux operating system
- Python 3.10 or newer
- Git
- pip
Install from Source
1. Clone the Repository
git clone https://github.com/arashhadikhani-sudo/container-inspect.git
cd container-inspect

2. Create a Virtual Environment
python3 -m venv .venv
source .venv/bin/activate

3. Upgrade pip
python -m pip install --upgrade pip

4. Install the Package
python -m pip install -e .

Verify Installation
Verify that the package can be imported:
python -c "import container_inspect; print('Installation successful')"

Check the installed package:
python -m pip show container-inspect

If the project provides a command-line interface, display its help:
container-inspect --help

Development Installation
Install development dependencies if the project defines a dev dependency group in pyproject.toml:
python -m pip install -e ".[dev]"

Run the test suite:
python -m pytest -v

Linux Permissions
container-inspect reads Linux process information from /proc.

Check that /proc is available:
ls /proc

Inspect the current process:
cat /proc/self/status

Some process information may require elevated permissions depending on system configuration and security restrictions.
Troubleshooting
Module Not Found
If Python cannot find the package, activate the virtual environment and reinstall it:
source .venv/bin/activate
python -m pip install -e .

Command Not Found
If container-inspect is unavailable, verify that the package defines a console-script entry point in pyproject.toml.
Permission Denied
Try inspecting a process owned by your user. Use sudo only when necessary.
Uninstall
Uninstall the package:
python -m pip uninstall container-inspect

Deactivate the virtual environment:
deactivate

To remove the virtual environment:
rm -rf .venv