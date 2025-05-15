import subprocess
import sys

# List of required packages
required_packages = [
    "flask",
    "werkzeug",
    "pyotp",
    "qrcode",
    "pillow",      # required by qrcode for image generation
    "shelve",      # part of Python's standard library
    "hashlib",     # part of Python's standard library
    "base64",      # part of Python's standard library
    "uuid",        # part of Python's standard library
    "wtforms"      # part of Python's standard library
]

# Filter out standard library modules
standard_libs = {"shelve", "hashlib", "base64", "uuid", "io", "os"}
packages_to_install = [pkg for pkg in required_packages if pkg.lower() not in standard_libs]

# Install missing packages
for package in packages_to_install:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    except subprocess.CalledProcessError as e:
        print(f"Failed to install {package}: {e}")
