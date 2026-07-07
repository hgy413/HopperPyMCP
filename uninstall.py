#!/usr/bin/env python3
"""
HopperPyMCP Uninstallation Script

Removes the FastMCP server script from your Hopper disassembler Scripts directory.

Usage:
    python uninstall.py [--confirm] [--dry-run]
"""

import sys
import os
import platform
import argparse
from pathlib import Path

HOPPER_SCRIPT_NAMES = ['Hopper MCP Start Server.py', 'fastmcp_server.py']


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


def find_installation():
    """Find existing HopperPyMCP installation."""
    
    print("🔍 Looking for existing installation...")
    
    hopper_dir = get_hopper_script_dir()
    for script_name in HOPPER_SCRIPT_NAMES:
        script_path = os.path.join(hopper_dir, script_name)
        if os.path.exists(script_path):
            print(f"   ✅ Found installation: {script_path}")
            return script_path

    print(f"   ❌ No installation found in: {hopper_dir}")
    return None


def remove_installation(script_path, dry_run=False):
    """Remove the installation."""
    
    if dry_run:
        print(f"🔍 Would remove: {script_path}")
        return
    
    try:
        os.remove(script_path)
        print(f"✅ Successfully removed: {script_path}")
    except OSError as e:
        print(f"❌ Failed to remove {script_path}: {e}")
        raise


def show_dependency_info():
    """Show information about dependencies that user might want to clean up."""
    
    print("\n📦 Dependency Information:")
    print("   The following packages were installed by HopperPyMCP:")
    print("   • fastmcp")
    print("   • pytest (development)")
    print("   • pytest-mock (development)")
    print("   • pytest-asyncio (development)")
    print("")
    print("   💡 If you want to remove these packages, run:")
    print("   pip uninstall fastmcp pytest pytest-mock pytest-asyncio")
    print("")
    print("   ⚠️  Warning: Only remove these if you're not using them elsewhere!")


def main():
    """Main uninstallation process."""
    
    parser = argparse.ArgumentParser(description='Uninstall HopperPyMCP from Hopper Scripts directory')
    parser.add_argument('--confirm', action='store_true', 
                       help='Skip confirmation prompt')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Show what would be done without actually doing it')
    args = parser.parse_args()
    
    print("🗑️  HopperPyMCP Uninstallation Script")
    print("=" * 50)
    
    try:
        # Find existing installation
        script_path = find_installation()
        
        if not script_path:
            print("❌ No HopperPyMCP installation found")
            print("💡 Nothing to uninstall")
            return
        
        # Confirm removal unless --confirm is specified
        if not args.confirm and not args.dry_run:
            response = input(f"\nRemove HopperPyMCP installation at {script_path}? (y/N): ")
            if response.lower() not in ['y', 'yes']:
                print("❌ Uninstallation cancelled")
                return
        
        # Remove the installation
        remove_installation(script_path, dry_run=args.dry_run)
        
        if not args.dry_run:
            print("\n" + "=" * 50)
            print("🎉 HopperPyMCP uninstalled successfully!")
            
            # Show dependency cleanup info
            show_dependency_info()
        else:
            print("\n" + "=" * 50)
            print("🔍 Dry run completed - no changes made")
        
    except KeyboardInterrupt:
        print("\n❌ Uninstallation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Uninstallation failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
