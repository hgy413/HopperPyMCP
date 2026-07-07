#!/usr/bin/env python3
"""
HopperPyMCP Installation Script

Automatically detects your Python environment (conda, uv, venv, or system Python)
and installs the FastMCP server script to your Hopper disassembler Scripts directory.

Usage:
    python install.py [--force] [--dry-run]
"""

import sys
import os
import platform
import shutil
import subprocess
import argparse
from pathlib import Path

HOPPER_SCRIPT_NAME = 'Hopper MCP Start Server.py'


def detect_python_environment():
    """Detect current Python environment and return environment information."""
    
    env_info = {
        'type': None,           # 'conda', 'venv', 'uv', 'system'
        'python_executable': sys.executable,
        'site_packages': [],
        'lib_path': None,
        'lib_dynload': None,
        'package_manager': None,  # 'conda', 'pip', 'uv'
        'environment_path': None
    }
    
    print("🔍 Detecting Python environment...")
    
    # Priority detection order:
    if os.environ.get('CONDA_PREFIX'):
        env_info['type'] = 'conda'
        env_info['package_manager'] = 'conda'
        env_info['environment_path'] = os.environ['CONDA_PREFIX']
        print(f"   ✅ Detected conda environment: {env_info['environment_path']}")
        
    elif os.environ.get('VIRTUAL_ENV'):
        env_info['type'] = 'venv'
        env_info['package_manager'] = 'pip'
        env_info['environment_path'] = os.environ['VIRTUAL_ENV']
        print(f"   ✅ Detected virtual environment: {env_info['environment_path']}")
        
    elif sys.prefix != sys.base_prefix:
        env_info['type'] = 'virtualenv'
        env_info['package_manager'] = 'pip'
        env_info['environment_path'] = sys.prefix
        print(f"   ✅ Detected virtual environment: {env_info['environment_path']}")
        
    else:
        env_info['type'] = 'system'
        env_info['package_manager'] = 'pip'
        env_info['environment_path'] = sys.prefix
        print(f"   ✅ Detected system Python: {env_info['environment_path']}")
    
    # Check for uv if present
    if shutil.which('uv') and (os.path.exists('.venv') or os.path.exists('uv.lock')):
        env_info['package_manager'] = 'uv'
        print("   ✅ uv package manager detected")
    
    return env_info


def get_python_paths(env_info):
    """Get the three critical paths needed for sys.path.insert()."""
    
    print("🔍 Determining Python paths...")
    
    if env_info['type'] == 'conda':
        # Use CONDA_PREFIX for conda environments
        conda_prefix = os.environ['CONDA_PREFIX']
        python_version = f"python{sys.version_info.major}.{sys.version_info.minor}"
        
        paths = {
            'lib_dynload': os.path.join(conda_prefix, 'lib', python_version, 'lib-dynload'),
            'lib_path': os.path.join(conda_prefix, 'lib', python_version),
            'site_packages': os.path.join(conda_prefix, 'lib', python_version, 'site-packages')
        }
        
        print(f"   📁 Using conda paths based on: {conda_prefix}")
        
    else:
        # Use site.getsitepackages() and sys.path analysis for other environments
        import site
        
        # Get site packages - handle multiple possible locations
        try:
            site_packages_list = site.getsitepackages()
            if site_packages_list:
                site_packages = site_packages_list[0]
            else:
                # Fallback for some virtualenvs
                site_packages = site.getusersitepackages()
        except AttributeError:
            # Some older virtualenv versions don't have getsitepackages
            site_packages = os.path.join(sys.prefix, 'lib', 
                                       f'python{sys.version_info.major}.{sys.version_info.minor}', 
                                       'site-packages')
        
        lib_path = os.path.dirname(site_packages)
        lib_dynload = os.path.join(lib_path, 'lib-dynload')
        
        paths = {
            'lib_dynload': lib_dynload,
            'lib_path': lib_path,
            'site_packages': site_packages
        }
        
        print(f"   📁 Using site-packages paths based on: {site_packages}")
    
    # Validate paths exist
    for path_name, path_value in paths.items():
        if os.path.exists(path_value):
            print(f"   ✅ {path_name}: {path_value}")
        else:
            print(f"   ⚠️  {path_name}: {path_value} (does not exist)")
    
    return paths


def get_hopper_script_dir():
    """Get Hopper script directory for current platform."""
    
    print("🔍 Determining Hopper Scripts directory...")
    
    system = platform.system().lower()
    home = os.path.expanduser('~')
    
    if system == 'darwin':  # macOS
        hopper_dir = os.path.join(home, 'Library', 'Application Support', 'Hopper', 'Scripts')
        print(f"   📁 macOS detected: {hopper_dir}")
    elif system == 'linux':
        hopper_dir = os.path.join(home, 'GNUstep', 'Library', 'ApplicationSupport', 'Hopper', 'Scripts')
        print(f"   📁 Linux detected: {hopper_dir}")
    else:
        raise OSError(f"❌ Unsupported platform: {system}. Only macOS and Linux are supported.")
    
    return hopper_dir


def install_dependencies(env_info, dry_run=False):
    """Install requirements using appropriate package manager."""
    
    print("📦 Installing dependencies...")
    
    if not os.path.exists('requirements.txt'):
        print("   ⚠️  requirements.txt not found, skipping dependency installation")
        return
    
    cmd = []
    if env_info['package_manager'] == 'conda':
        # Try pip within conda environment (more reliable than conda install)
        cmd = [sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt']
        print("   🔧 Using pip within conda environment")
        
    elif env_info['package_manager'] == 'uv':
        cmd = ['uv', 'pip', 'install', '-r', 'requirements.txt']
        print("   🔧 Using uv pip")
        
    else:  # pip
        cmd = [sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt']
        print("   🔧 Using pip")
    
    if dry_run:
        print(f"   🔍 Would run: {' '.join(cmd)}")
        return
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("   ✅ Dependencies installed successfully")
        if result.stdout:
            print(f"   📝 Output: {result.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        print(f"   ❌ Failed to install dependencies: {e}")
        if e.stderr:
            print(f"   📝 Error: {e.stderr.strip()}")
        raise
    except FileNotFoundError:
        print(f"   ❌ Package manager '{env_info['package_manager']}' not found")
        raise


def substitute_template(template_path, output_path, substitutions, dry_run=False):
    """Replace placeholders in template with actual paths."""
    
    print(f"🔧 Creating configured script from template...")
    
    if not os.path.exists(template_path):
        raise FileNotFoundError(f"Template file not found: {template_path}")
    
    with open(template_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    print("   🔍 Applying substitutions:")
    for placeholder, value in substitutions.items():
        print(f"      {placeholder} -> {value}")
        content = content.replace(placeholder, value)
    
    if dry_run:
        print(f"   🔍 Would write configured script to: {output_path}")
        return
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"   ✅ Configured script created: {output_path}")


def validate_installation():
    """Validate that FastMCP can be imported after installation."""
    
    print("🔍 Validating installation...")
    
    try:
        import fastmcp
        print("   ✅ FastMCP import successful")
        return True
    except ImportError as e:
        print(f"   ❌ FastMCP import failed: {e}")
        print("   💡 You may need to install dependencies manually")
        return False


def main():
    """Main installation process."""
    
    parser = argparse.ArgumentParser(description='Install HopperPyMCP to Hopper Scripts directory')
    parser.add_argument('--force', action='store_true', 
                       help='Overwrite existing installation without prompting')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Show what would be done without actually doing it')
    args = parser.parse_args()
    
    print("🚀 HopperPyMCP Installation Script")
    print("=" * 50)
    
    try:
        # 1. Detect environment
        env_info = detect_python_environment()
        
        # 2. Get Python paths
        paths = get_python_paths(env_info)
        
        # 3. Validate template exists
        template_path = 'fastmcp_server_template.py'
        if not os.path.exists(template_path):
            print(f"❌ Template file not found: {template_path}")
            print("💡 Make sure you're running this script from the HopperPyMCP directory")
            sys.exit(1)
        
        # 4. Install dependencies
        install_dependencies(env_info, dry_run=args.dry_run)
        
        # 5. Validate FastMCP is available
        if not args.dry_run:
            if not validate_installation():
                print("⚠️  Warning: FastMCP validation failed, but continuing with installation")
        
        # 6. Create script from template
        configured_script = 'fastmcp_server_configured.py'
        substitutions = {
            '{{PYTHON_LIB_DYNLOAD}}': paths['lib_dynload'],
            '{{PYTHON_LIB_PATH}}': paths['lib_path'],
            '{{PYTHON_SITE_PACKAGES}}': paths['site_packages']
        }
        
        substitute_template(template_path, configured_script, substitutions, dry_run=args.dry_run)
        
        # 7. Install to Hopper directory
        hopper_dir = get_hopper_script_dir()
        target_path = os.path.join(hopper_dir, HOPPER_SCRIPT_NAME)
        
        if args.dry_run:
            print(f"🔍 Would create directory: {hopper_dir}")
            print(f"🔍 Would copy script to: {target_path}")
        else:
            # Check if target already exists
            if os.path.exists(target_path) and not args.force:
                response = input(f"Script already exists at {target_path}. Overwrite? (y/N): ")
                if response.lower() not in ['y', 'yes']:
                    print("❌ Installation cancelled")
                    sys.exit(1)
            
            # Create directory and copy file
            os.makedirs(hopper_dir, exist_ok=True)
            shutil.copy2(configured_script, target_path)
            
            print(f"✅ Successfully installed to: {target_path}")
        
        print("\n" + "=" * 50)
        print("🎉 Installation completed successfully!")
        print(f"📁 Script location: {target_path}")
        print("💡 You can now use the script from within Hopper!")
        print("💡 Run 'python uninstall.py' to remove the installation")
        
        # Clean up temporary file
        if not args.dry_run and os.path.exists(configured_script):
            os.remove(configured_script)
        
    except KeyboardInterrupt:
        print("\n❌ Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Installation failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
