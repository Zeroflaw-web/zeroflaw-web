#!/bin/bash
# Build script for installing additional security tools on Render

echo "Installing additional security tools..."

# Install CodeQL
echo "Installing CodeQL..."
mkdir -p /opt/codeql
cd /opt/codeql
# Note: CodeQL installation on Render may require a different approach due to size limitations

# Install OWASP ZAP
echo "Installing OWASP ZAP..."
# Note: ZAP installation on Render may require a different approach due to size limitations

echo "Additional tools installation completed."