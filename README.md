# HopperPyMCP - FastMCP Server for Hopper Disassembler

A FastMCP server plugin for the Hopper disassembler that provides powerful analysis tools through the Model Context Protocol (MCP). This plugin allows you to analyze binary files, disassemble procedures, manage documents, and more through AI assistants.

## Features

- 🔍 **Binary Analysis**: Analyze segments, procedures, and data structures
- 🛠️ **Disassembly & Decompilation**: Get detailed assembly and pseudo-code output
- 📊 **Call Graph Generation**: Visualize function relationships and program flow
- 🔗 **Reference Analysis**: Track memory references and cross-references
- 📝 **Annotation Tools**: Add names, comments, and type information
- 🗂️ **Document Management**: Handle multiple executable files
- 🔍 **String Search**: Advanced regex-based string searching

## Quick Installation

The installation process automatically detects your Python environment (conda, uv, venv, or system Python) and configures everything for you:

```bash
# Simple one-command installation
python install.py
```

That's it! The script will:
- ✅ Detect your Python environment automatically
- ✅ Install required dependencies (fastmcp)
- ✅ Configure the script with correct Python paths
- ✅ Install to the appropriate Hopper Scripts directory

### Supported Environments

- **Conda environments** (including miniconda/anaconda)
- **UV virtual environments** 
- **Python venv/virtualenv**
- **System Python installations**
- **macOS and Linux platforms**

If you use an environment like conda, uv, or virtualenv, run the install script from within a new environment, since dependencies will be installed by install.py.

## Manual Installation Options

### Dry Run (Preview Changes)
```bash
# See what would be installed without making changes
python install.py --dry-run
```

### Force Installation
```bash
# Overwrite existing installation without prompting
python install.py --force
```

## Uninstallation

Remove the plugin cleanly:

```bash
# Remove the installation
python uninstall.py

# Preview what would be removed
python uninstall.py --dry-run

# Remove without confirmation
python uninstall.py --confirm
```

## Usage in Hopper

Once installed, the Hopper script is triggered on demand by `hopper_mcp_bridge.py`.
Each MCP call writes one request file, runs `Scripts > Hopper MCP Start Server`
inside Hopper, writes one response file, and exits immediately. Hopper may show
`Executing Python Script...` briefly for each request, but there is no long-lived
foreground Python task.

### String Cache

Due to slow Hopper string APIs, the plugin can create optimized string caches for
better performance. This process takes about 5-10 minutes per document and saves
caches alongside your Hopper document saves.

In the Hopper Python prompt, paste:

```python
cache_strings()
```

The on-demand runner provides the following tools:

### Document Management

- [`get_all_documents()`](fastmcp_server_template.py:329) - Get information about all currently opened documents (Hopper-analyzed binaries)
- [`get_current_document()`](fastmcp_server_template.py:355) - Get information about the current document with its doc_id
- [`set_current_document(doc_id)`](fastmcp_server_template.py:386) - Set the current document by doc_id
- [`rebase_document(new_base_address_hex)`](fastmcp_server_template.py:408) - Rebase the current document to a new base address

### Core Analysis Tools

- [`list_all_segments()`](fastmcp_server_template.py:424) - List all segments in the current document with basic information
- [`get_address_info(address_or_name_list)`](fastmcp_server_template.py:641) - Get comprehensive information about multiple addresses/names including segment, section, type, procedure info, and references

### Search and Discovery

- [`search_names_regex(regex_pattern, segment_name, search_type, max_results)`](fastmcp_server_template.py:459) - Search for names matching a regex pattern in a specific segment
- [`search_strings_regex(regex_pattern, segment_name, max_results)`](fastmcp_server_template.py:567) - Search for strings matching a regex pattern in a specific segment
- [`get_string_at_addr(address_hex)`](fastmcp_server_template.py:618) - Get the string content at a specific address using the cached strings list

### Disassembly & Decompilation

- [`disassemble_procedure(address_or_name)`](fastmcp_server_template.py:1008) - Disassemble a procedure into assembly language instructions
- [`decompile_procedure(address_or_name)`](fastmcp_server_template.py:973) - Decompile a procedure to C language code

### Call Graph Generation

- [`get_call_graph(start_addr_hex, direction, max_depth)`](fastmcp_server_template.py:819) - Return the call graph starting from a specific address

### Name and Symbol Analysis

- [`get_demangled_name(address_or_name)`](fastmcp_server_template.py:1086) - Get the demangled name at a specific address or for a given name

### Comments and Annotations

- [`get_comment_at_address(address_hex)`](fastmcp_server_template.py:1115) - Get the comment at a specific address
- [`set_comment_at_address(address_hex, comment)`](fastmcp_server_template.py:1133) - Set a comment at a specific address
- [`set_name_at_address(address_hex, name)`](fastmcp_server_template.py:1155) - Set a name/label at a specific address
- [`mark_data_type_at_address(address_hex, data_type, length)`](fastmcp_server_template.py:1173) - Mark data type at a specific address

## Requirements

- Python 3.8+
- Hopper Disassembler v4 or v5
- FastMCP library (automatically installed)

## File Structure

```
HopperPyMCP/
├── install.py                    # Main installation script
├── uninstall.py                  # Uninstallation script
├── fastmcp_server.py             # Current working version
├── fastmcp_server_template.py    # Template with placeholders
├── requirements.txt              # Python dependencies
├── tests/                        # Test suite
└── README.md                     # This file
```

## Troubleshooting

### Installation Issues

**Problem**: `fastmcp` import fails after installation
```bash
# Solution: Manually install dependencies
pip install fastmcp
# or for conda:
conda install -c conda-forge fastmcp
```

**Problem**: Permission denied when writing to Hopper directory
```bash
# Solution: Check Hopper directory permissions
ls -la ~/Library/Application\ Support/Hopper/Scripts/  # macOS
ls -la ~/GNUstep/Library/ApplicationSupport/Hopper/Scripts/  # Linux
```

**Problem**: Wrong Python environment detected
```bash
# Solution: Activate the correct environment first
conda activate your-environment  # for conda
source your-venv/bin/activate    # for venv
# Then run install.py
```

### Runtime Issues

**Problem**: Script not appearing in Hopper
- Verify installation path is correct for your platform
- Check Hopper Scripts directory exists and is readable
- Restart Hopper after installation

**Problem**: Import errors when running in Hopper
- The installation should handle Python path configuration automatically
- If issues persist, check that the installed script has the correct paths

### Platform-Specific Notes

**macOS**: Scripts install to `~/Library/Application Support/Hopper/Scripts/`
**Linux**: Scripts install to `~/GNUstep/Library/ApplicationSupport/Hopper/Scripts/`

## Development

### Running Tests
```bash
# Run the test suite
python -m pytest tests/
```

### Development Installation
For development, you might want to symlink instead of copy:
```bash
# Manual symlink for development
ln -s $(pwd)/fastmcp_server.py ~/Library/Application\ Support/Hopper/Scripts/
```

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review the test files for usage examples
3. Open an issue on the project repository

---

**Note**: This plugin requires Hopper's built-in Python interpreter. The installation script automatically configures the necessary Python paths for seamless integration.
