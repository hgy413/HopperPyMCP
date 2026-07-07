#!/usr/bin/env python3
"""
FastMCP server for Hopper disassembler integration.
Provides tools for analyzing binary files, disassembling procedures, and managing documents.
"""

import sys
import os

import re
import json
import time
import traceback
from typing import Annotated, TYPE_CHECKING

IN_HOPPER = "python" not in os.path.basename(sys.executable).lower()
LOG_PATH = "/tmp/hopper_mcp_start.log"
REQUEST_DIR = "/tmp/hopper_mcp_requests"
REQUEST_SUFFIX = ".request.json"
RUNNING_SUFFIX = ".running.json"
RESPONSE_SUFFIX = ".response.json"

def _log(message):
    if not IN_HOPPER:
        return
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as log_file:
            log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")
    except Exception:
        pass

_log(f"script loaded with executable={sys.executable}")

# This import must be conditional because hopper imports it automatically when run as a plugin
if TYPE_CHECKING or not IN_HOPPER:
    from tests.hopper_api import Document, Procedure, Segment

if IN_HOPPER:
    # Hopper v4 embeds Python 3.9, while current FastMCP requires Python 3.10+.
    # Keep the Hopper-side script stdlib-only; Codex talks through request files.
    def Field(*args, **kwargs):
        return {"args": args, **kwargs}

    class LocalToolRegistry:
        def __init__(self, name):
            self.name = name
            self.tools = {}

        def tool(self, func):
            self.tools[func.__name__] = func
            return func
else:
    from pydantic import Field
    from fastmcp import FastMCP

# Monkey patch sys.stdout.isatty() to return False
def _isatty_false():
    return False

sys.stdout.isatty = _isatty_false

doc = Document.getCurrentDocument()

# Global cache for segment strings
_segment_strings_cache = {}

# Create a FastMCP server instance
mcp = LocalToolRegistry(name="Hopper MCP Runner") if IN_HOPPER else FastMCP(name="Hopper MCP")

############## Helper functions for common operations #################3
def is_hopper_not_found(value):
    """Check if a Hopper API return value indicates 'not found'.
    
    Hopper API functions return 0xffffffffffffffff when a name/address is not found.
    This helper provides consistent checking across all functions.
    """
    return value is None or value == 0xffffffffffffffff

def is_hopper_not_found_allow_zero(value):
    """Check if a Hopper API return value indicates 'not found', including 0.
    
    Some older Hopper versions or certain functions may return 0 instead of 0xffffffffffffffff.
    This helper checks for both cases for backwards compatibility.
    """
    return value is None or value == 0 or value == 0xffffffffffffffff

def is_valid_segment(segment) -> bool:
    """Check if a segment object is valid.
    
    Since hopper_api.py may return a Segment object even when the underlying
    address is invalid (0xffffffffffffffff), we need to check if the segment
    is actually usable.
    """
    if segment is None:
        return False
    try:
        # Try to get the segment name - this will fail if the segment is invalid
        name = segment.getName()
        return name is not None and name != ""
    except:
        return False

def get_procedure_name_with_fallback(addr):
    """Get procedure name with consistent fallback logic"""
    seg = doc.getSegmentAtAddress(addr)
    if not seg:
        return f"0x{addr:x}"
    
    proc = seg.getProcedureAtAddress(addr)
    name = seg.getNameAtAddress(addr)
    
    # If no name at address but we have a procedure, try entry point
    if not name and proc:
        name = seg.getNameAtAddress(proc.getEntryPoint())
    
    # Final fallback to address format
    if not name:
        name = f"0x{addr:x}"
        
    return name

def get_cache_file_path():
    """Get the cache file path based on the current Hopper document location"""
    db_path = doc.getDatabaseFilePath()
    if db_path:
        return db_path + ".mcpcache"
    return None

def load_disk_cache():
    """Load the cache from disk if it exists"""
    cache_path = get_cache_file_path()
    if not cache_path:
        return {}
    
    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            cache_data = data.get("strings_cache_v1", {})
            
            # Convert lists back to tuples since JSON doesn't preserve tuples
            for key, value in cache_data.items():
                if isinstance(value, list):
                    cache_data[key] = [tuple(item) if isinstance(item, list) else item for item in value]
            
            return cache_data
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return {}

def save_disk_cache(cache_data):
    """Save the cache to disk"""
    cache_path = get_cache_file_path()
    if not cache_path:
        return
    
    try:
        cache_structure = {"strings_cache_v1": cache_data}
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(cache_structure, f, indent=2)
    except (IOError, OSError):
        # Silently fail if we can't write the cache file
        pass

def get_cached_strings_list(segment):
    """Get cached strings list for a segment, using getStringsList() for efficiency.
    
    Checks disk cache first, then memory cache, then generates fresh data.
    Saves to both memory and disk when generating new data.
    """
    global _segment_strings_cache
    
    segment_name = segment.getName()
    segment_start = segment.getStartingAddress()
    cache_key = f"{segment_name}_{segment_start:x}"
    
    # Check memory cache first
    if cache_key in _segment_strings_cache:
        return _segment_strings_cache[cache_key]
    
    # Load disk cache if memory cache is empty
    if not _segment_strings_cache:
        disk_cache = load_disk_cache()
        _segment_strings_cache.update(disk_cache)
    
    # Check if we now have the data in memory after loading from disk
    if cache_key in _segment_strings_cache:
        return _segment_strings_cache[cache_key]
    
    # Generate fresh data
    strings_data = segment.getStringsList()
    _segment_strings_cache[cache_key] = strings_data
    
    # Save updated cache to disk
    save_disk_cache(_segment_strings_cache)
    
    return strings_data

def get_cache_file_path_for_document(document):
    """Get the cache file path for a specific document"""
    db_path = document.getDatabaseFilePath()
    if db_path:
        return db_path + ".mcpcache"
    return None

def load_disk_cache_for_document(document):
    """Load the cache from disk for a specific document"""
    cache_path = get_cache_file_path_for_document(document)
    if not cache_path:
        return {}
    
    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            cache_data = data.get("strings_cache_v1", {})
            
            # Convert lists back to tuples since JSON doesn't preserve tuples
            for key, value in cache_data.items():
                if isinstance(value, list):
                    cache_data[key] = [tuple(item) if isinstance(item, list) else item for item in value]
            
            return cache_data
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return {}

def save_disk_cache_for_document(document, cache_data):
    """Save the cache to disk for a specific document"""
    cache_path = get_cache_file_path_for_document(document)
    if not cache_path:
        return False
    
    try:
        cache_structure = {"strings_cache_v1": cache_data}
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(cache_structure, f, indent=2)
        return True
    except (IOError, OSError):
        return False

def check_document_has_complete_string_cache(document):
    """Check if a document has complete string cache for all segments with strings"""
    cache_data = load_disk_cache_for_document(document)
    
    # Check all segments in the document
    for i in range(document.getSegmentCount()):
        segment = document.getSegment(i)
        if segment and segment.getStringCount() > 0:
            # This segment has strings, check if it's cached
            segment_name = segment.getName()
            segment_start = segment.getStartingAddress()
            cache_key = f"{segment_name}_{segment_start:x}"
            
            if cache_key not in cache_data:
                return False
    
    return True

def create_string_cache_for_document(document):
    """Create and save string cache for all segments in a document"""
    cache_data = {}
    
    # Process all segments
    for i in range(document.getSegmentCount()):
        segment = document.getSegment(i)
        if segment and segment.getStringCount() > 0:
            # This segment has strings, cache them
            segment_name = segment.getName()
            segment_start = segment.getStartingAddress()
            cache_key = f"{segment_name}_{segment_start:x}"
            
            # Get strings data using the same method as get_cached_strings_list
            strings_data = segment.getStringsList()
            cache_data[cache_key] = strings_data
    
    # Save the cache to disk
    return save_disk_cache_for_document(document, cache_data)

def check_all_documents_have_string_caches():
    """Check if all open documents have complete string caches"""
    all_docs = Document.getAllDocuments()
    
    for document in all_docs:
        if not check_document_has_complete_string_cache(document):
            return False
    
    return True

def create_string_caches_for_all_documents():
    """Create and save string caches for all open documents"""
    all_docs = Document.getAllDocuments()
    all_success = True
    
    for document in all_docs:
        # Check if document has a hopper database
        db_path = document.getDatabaseFilePath()
        if not db_path:
            print(f"Document '{document.getDocumentName()}' needs to be saved first before caching strings")
            return False
            
        # Try to create cache for this document
        if not create_string_cache_for_document(document):
            return False
    
    return True

def parse_hex_address(address_hex):
    """Parse hex address string to integer with validation"""
    try:
        return int(address_hex, 16)
    except ValueError:
        raise ValueError(f"Invalid hex address format: '{address_hex}'")

def resolve_address_or_name_auto(address_or_name):
    """Automatically resolve address from either hex string (starting with 0x) or name lookup.
    
    Args:
        address_or_name: String that is either a hex address (e.g., "0x1000", "1000") or a name
        
    Returns:
        int: The resolved address
        
    Raises:
        ValueError: If the address format is invalid or name is not found
    """
    if address_or_name.lower().startswith('0x'):
        # It's a hex address
        return parse_hex_address(address_or_name)
    else:
        # It's a name - try to resolve it
        address = doc.getAddressForName(address_or_name)
        if is_hopper_not_found_allow_zero(address):
            raise ValueError(f"No address found for name '{address_or_name}'")
        return address

def get_segment_and_procedure(address):
    """Get segment and procedure at address with validation"""
    segment = doc.getSegmentAtAddress(address)
    if not segment:
        raise ValueError(f"No segment found at address 0x{address:x}")
    
    procedure = segment.getProcedureAtAddress(address)
    if not procedure:
        raise ValueError(f"No procedure found at address 0x{address:x}")
    
    return segment, procedure

def get_procedure_names(segment, address):
    """Get regular and demangled names for a procedure"""
    regular_name = segment.getNameAtAddress(address)
    demangled_name = segment.getDemangledNameAtAddress(address)
    return regular_name, demangled_name

############################ MCP Tools ###############################

@mcp.tool
def get_all_documents() -> dict:
    """Get information about all currently opened documents (Hopper-analyzed binaries).
    
    Each document represents a separate executable file. Returns a list with
    document information where each has a doc_id for switching between documents.
    """
    all_docs = Document.getAllDocuments()
    result = {
        "total_documents": len(all_docs),
        "documents": []
    }
    
    for i, document in enumerate(all_docs):
        doc_info = {
            "doc_id": i,
            "document_name": document.getDocumentName(),
            "executable_path": document.getExecutableFilePath(),
            "entry_point": f"0x{document.getEntryPoint():x}",
            "segment_count": document.getSegmentCount(),
            "analysis_active": document.backgroundProcessActive()
        }
        result["documents"].append(doc_info)
    
    return result

@mcp.tool
def get_current_document() -> dict:
    """Get information about the current document with its doc_id.
    
    Returns information about the currently active executable file being analyzed,
    including the doc_id needed to switch back to this document later.
    """
    if "python" in sys.executable:
        all_docs = Document.getAllDocuments()
    else:
        all_docs = [doc] #XXX: This is buggy: Document.getAllDocuments()
    current_doc = doc  # Use the global doc variable instead of getCurrentDocument()
    
    # Find the index of the current document in the all_docs list
    doc_id = -1
    for i, document in enumerate(all_docs):
        if document == current_doc:
            doc_id = i
            break
    
    result = {
        "doc_id": doc_id,
        "document_name": current_doc.getDocumentName(),
        "executable_path": current_doc.getExecutableFilePath(),
        "entry_point": f"0x{current_doc.getEntryPoint():x}",
        "segment_count": current_doc.getSegmentCount(),
        "analysis_active": current_doc.backgroundProcessActive()
    }
    
    return result

@mcp.tool
def set_current_document(doc_id: Annotated[int, Field(description="The document ID from get_all_documents() or get_current_document()", ge=0)]) -> str:
    """Set the current document by doc_id.
    
    Switches the active executable file being analyzed. Use doc_id from
    get_all_documents() or get_current_document() to specify which document.
    """
    global doc, _segment_strings_cache
    
    all_docs = Document.getAllDocuments()
    
    if doc_id < 0 or doc_id >= len(all_docs):
        raise ValueError(f"Invalid doc_id {doc_id}. Valid range is 0 to {len(all_docs) - 1}")
    
    # Clear the strings cache when switching documents
    _segment_strings_cache.clear()
    
    # Set the new current document
    doc = all_docs[doc_id]
    
    return f"Successfully set current document to doc_id {doc_id}: {doc.getDocumentName()}"

@mcp.tool
def rebase_document(new_base_address_hex: Annotated[str, "The new base address for the document as hex string (e.g., '0x1000')"]) -> str:
    """Rebase the current document to a new base address.
    
    Rebasing changes the base memory address where the executable is loaded,
    updating all address references throughout the document accordingly.
    
    WORKFLOW HINT: This should typically be called FIRST when analyzing crash dumps
    or backtrace lists to align addresses with the actual runtime loading location.
    After rebasing, use list_all_segments() to get an overview of the new layout.
    """
    new_base_address = int(new_base_address_hex, 16)
    doc.rebase(new_base_address)
    doc.saveDocument()
    return f"Successfully rebased document to address 0x{new_base_address:x}"

@mcp.tool
def list_all_segments() -> dict:
    """List all segments in the current document with basic information.
    
    Segments are the main memory regions that make up the executable file,
    such as text segments (code+data), data segments (variables and structs),
    imports, etc.
    
    WORKFLOW HINT: Use this tool to get an overview of the binary structure.
    Follow up with search_names_regex and search_strings_regex for detailed
    examination of specific segments.
    """
    segments_info = []
    for i in range(doc.getSegmentCount()):
        segment = doc.getSegment(i)
        if segment:
            segment_info = {
                "index": i,
                "name": segment.getName(),
                "start_address": f"0x{segment.getStartingAddress():x}",
                "length": segment.getLength(),
                "section_count": segment.getSectionCount(),
                "procedure_count": segment.getProcedureCount(),
                "string_count": segment.getStringCount(),
                "total_names_count": segment.getLabelCount()
            }
            segments_info.append(segment_info)
    
    result = {
        "total_segments": doc.getSegmentCount(),
        "segments": segments_info
    }
    
    return result

@mcp.tool
def search_names_regex(
    regex_pattern: Annotated[str, "Regular expression pattern to search for in names"],
    segment_name: Annotated[str, "Target segment name to search in (e.g., 'TEXT', 'DATA')"],
    search_type: Annotated[str, "Type of names to search: 'bare', 'demangled', or 'both'"] = "both",
    max_results: Annotated[int, Field(description="Maximum number of results to return", ge=1)] = 20
) -> dict:
    """Search for names matching a regex pattern in a specific segment. Use list_all_segments()
    first to see available segments. Searches all named addresses: procedures, labels,
    variable names, string names, import names, struct names. Can search bare names,
    demangled names, or both.

    WORKFLOW HINT: Most binaries are stripped, so they often will not have
    named functions or named variables (these are instead numbered by Hopper). String names
    are often still present, and imports of system libraries and frameworks are always preserved.
    Searching for system libraries and framework functions is typically the best way to use
    this tool. Once interesting names are found, use the get_address_info() tool and/or
    get_call_graph() tools, depending on the type of the name.
    """
    pattern = re.compile(regex_pattern)
    
    if search_type not in ["bare", "demangled", "both"]:
        raise ValueError("search_type must be 'bare', 'demangled', or 'both'")
    
    matches = []
    
    # Get target segment
    segment = doc.getSegmentByName(segment_name)
    if not segment or not is_valid_segment(segment):
        raise ValueError(f"No segment found with name '{segment_name}'")
    
    # Get all named addresses in the segment
    named_addresses = segment.getNamedAddresses()
    
    # Search all named addresses until we find max_results matches or finish all names
    for addr in named_addresses:
        if len(matches) >= max_results:
            break
            
        # Get both bare and demangled names
        bare_name = segment.getNameAtAddress(addr)
        demangled_name = segment.getDemangledNameAtAddress(addr)
        
        # Determine which names to search based on search_type
        names_to_search = []
        if search_type in ["bare", "both"] and bare_name:
            names_to_search.append(("bare", bare_name))
        if search_type in ["demangled", "both"] and demangled_name and demangled_name != bare_name:
            names_to_search.append(("demangled", demangled_name))
        
        # Check if any name matches pattern
        matched_names = []
        for name_type, name_value in names_to_search:
            if pattern.search(name_value):
                matched_names.append((name_type, name_value))
        
        if matched_names:
            # Build comprehensive name info
            name_info = {}
            name_info["address"] = f"0x{addr:x}"

            # Add bare name if available
            if bare_name:
                name_info["bare_name"] = bare_name
            
            # Add demangled name if different from bare name
            if demangled_name and demangled_name != bare_name:
                name_info["demangled_name"] = demangled_name
            
            # Get data type information
            data_type = segment.getTypeAtAddress(addr)
            if data_type is not None:
                name_info["type"] = Segment.stringForType(data_type)
            
            # Check if there's a procedure at this address
            procedure = segment.getProcedureAtAddress(addr)
            if procedure:
                proc_info = {
                    "entry_point": f"0x{procedure.getEntryPoint():x}",
                    "basic_block_count": procedure.getBasicBlockCount(),
                    "heap_size": procedure.getHeapSize()
                }
                
                # Add signature if available
                signature = procedure.signatureString()
                if signature:
                    proc_info["signature"] = signature
                
                name_info["procedure"] = proc_info
            
            # Add comment if available
            comment = segment.getCommentAtAddress(addr)
            if comment:
                name_info["comment"] = comment
            
            matches.append(name_info)
    
    # Determine if search was completed
    search_finished = len(matches) < max_results or len(matches) == 0
    
    return {
        "matches": matches,
        "num_results": len(matches),
        "max_results": max_results,
        "search_type": search_type,
        "search_finished": search_finished
    }

@mcp.tool
def search_strings_regex(
    regex_pattern: Annotated[str, "Regular expression pattern to search for in strings"],
    segment_name: Annotated[str, "Target segment name to search in (e.g., 'TEXT', 'DATA')"],
    max_results: Annotated[int, Field(description="Maximum number of results to return", ge=1)] = 20
) -> dict:
    """Search for strings matching a regex pattern in a specific segment. Use list_all_segments()
    first to see available segment names.
    
    Searches all strings in the segment until max_results matches are found or all strings
    have been checked. Use get_address_info() to find references to interesting strings.
    """
    pattern = re.compile(regex_pattern)
    
    matches = []
    
    # Get target segment
    segment = doc.getSegmentByName(segment_name)
    if not segment or not is_valid_segment(segment):
        raise ValueError(f"No segment found with name '{segment_name}'")
    
    # Use cached strings list for efficiency
    strings_list = get_cached_strings_list(segment)
    
    # Search all strings until we find max_results matches or finish all strings
    for addr, string_value in strings_list:
        if len(matches) >= max_results:
            break
            
        # Check if string matches pattern
        if pattern.search(string_value):
            string_info = {
                "address": f"0x{addr:x}",
                "content": string_value
            }
            # Add name if available
            name_at_addr = doc.getNameAtAddress(addr)
            if name_at_addr:
                string_info["name"] = name_at_addr
            matches.append(string_info)
    
    # Determine if search was completed
    search_finished = len(matches) < max_results or len(matches) == 0
    
    return {
        "matches": matches,
        "num_results": len(matches),
        "max_results": max_results,
        "search_finished": search_finished
    }

@mcp.tool
def get_string_at_addr(address_hex: Annotated[str, "The memory address as hex string (e.g., '0x1000')"]) -> str:
    """Get the string content at a specific address using the cached strings list.
    
    Searches the cached strings list for the segment containing the address
    and returns the string content if found at that exact address.
    """
    address = parse_hex_address(address_hex)
    
    segment = doc.getSegmentAtAddress(address)
    if not segment:
        raise ValueError(f"No segment found at address 0x{address:x}")
    
    # Get cached strings list for efficiency
    strings_list = get_cached_strings_list(segment)
    
    # Search for the exact address in the strings list
    for string_addr, string_content in strings_list:
        if string_addr == address:
            return f"String at 0x{address:x}: {string_content}"
    
    return f"No string found at address 0x{address:x}"

@mcp.tool
def get_address_info(address_or_name_list: Annotated[list[str], "List of memory addresses as hex strings (e.g., '0x1000') or names that can be mixed"]) -> dict:
    """Get comprehensive information about multiple addresses/names including segment, section, type, procedure info, and references.
    
    Returns a dict of dicts where top-level keys are the queried addresses/names from the input list,
    and values are the comprehensive analysis for each address. Provides complete analysis of what exists
    at specific memory addresses: the containing segment/section, data type, any names/comments,
    associated procedures, and detailed reference information showing what references this address
    and what it references. Can accept a mix of hex addresses (starting with 0x) and procedure/symbol names.
    
    WORKFLOW HINT: This is the primary tool for detailed address analysis. Use after
    identify addresses of interest through search_names_regex(), search_strings_rege(), 
    decompile_procedure(), or disassemble_procedure(). For call relationships, consider
    generate_call_graph() for broader context.
    """
    if not address_or_name_list:
        raise ValueError("address_or_name_list cannot be empty")
    
    if len(address_or_name_list) > 50:  # Limit batch size for performance
        raise ValueError("Maximum 50 addresses allowed per batch")
    
    results = {}
    
    for address_or_name in address_or_name_list:
        try:
            address = resolve_address_or_name_auto(address_or_name)
            
            segment = doc.getSegmentAtAddress(address)
            if not segment:
                raise ValueError(f"No segment found at address 0x{address:x}")
            
            result = {
                "address": f"0x{address:x}",
                "segment": {
                    "name": segment.getName(),
                    "start_address": f"0x{segment.getStartingAddress():x}",
                }
            }
                
            # Get section information
            section_info = None
            section_start = None
            for i in range(segment.getSectionCount()):
                section = segment.getSection(i)
                if section:
                    section_start = section.getStartingAddress()
                    section_end = section_start + section.getLength()
                    if section_start <= address < section_end:
                        section_info = {
                            "name": section.getName(),
                            "start_address": f"0x{section_start:x}",
                            "flags": section.getFlags()
                        }
                        break
            
            if section_info:
                result["section"] = section_info
            
            # Get type information for the address
            data_type = segment.getTypeAtAddress(address)
            if data_type is not None:
                result["type"] = Segment.stringForType(data_type)
            
            # Get name if available (including segment base)
            name = segment.getNameAtAddress(address)
            if name:
                result["name"] = name
            
            # Get comment if available
            comment = segment.getCommentAtAddress(address)
            if comment:
                result["comment"] = comment
            
            # Get demangled name if available (including segment base)
            demangled_name = segment.getDemangledNameAtAddress(address)
            if demangled_name and demangled_name != name:
                result["demangled_name"] = demangled_name
            
            # Check if there's a procedure at this address or at the start of the section
            procedure = segment.getProcedureAtAddress(address)
            if procedure:
                result["procedure"] = {
                    "entry_point": f"0x{procedure.getEntryPoint():x}",
                    "basic_block_count": procedure.getBasicBlockCount()
                }
                
                # Add signature if available
                signature = procedure.signatureString()
                if signature:
                    result["procedure"]["signature"] = signature
                
                proc_regular_name, proc_demangled_name = get_procedure_names(segment, procedure.getEntryPoint())
                if proc_demangled_name and proc_demangled_name != name:
                    result["procedure"]["demangled_name"] = proc_demangled_name
           
            # If it's an instruction, include simplified instruction details
            instruction = segment.getInstructionAtAddress(address)
            if instruction:
                # Build flat disassembly string
                disasm_string = instruction.getInstructionString()
                
                # Add formatted arguments if available
                if instruction.getArgumentCount() > 0:
                    args = []
                    for i in range(instruction.getArgumentCount()):
                        formatted_arg = instruction.getFormattedArgument(i)
                        if formatted_arg:
                            args.append(formatted_arg)
                    if args:
                        disasm_string += " " + ", ".join(args)
                
                result["instruction"] = {
                    "disassembly": disasm_string,
                    "architecture": instruction.stringForArchitecture(instruction.getArchitecture())
                }
            
            # Get comprehensive reference information
            # Direct references to this address
            references_to = segment.getReferencesOfAddress(address)
            direct_refs_to = []
            if references_to:
                for ref_addr in references_to:
                    ref_name = doc.getNameAtAddress(ref_addr)
                    ref_info = {
                        "address": f"0x{ref_addr:x}",
                    }
                    if ref_name:
                        ref_info["name"] = ref_name

                    ref_seg = doc.getSegmentAtAddress(ref_addr)
                    data_type = None
                    if ref_seg:
                        data_type = ref_seg.getTypeAtAddress(ref_addr)

                    if data_type is not None:
                        ref_info["type"] = Segment.stringForType(data_type)
                    direct_refs_to.append(ref_info)
            
            # Direct references from this address
            references_from = segment.getReferencesFromAddress(address)
            direct_refs_from = []
            if references_from:
                for ref_addr in references_from:
                    ref_name = doc.getNameAtAddress(ref_addr)
                    ref_info = {
                        "address": f"0x{ref_addr:x}",
                    }
                    if ref_name:
                        ref_info["name"] = ref_name

                    ref_seg = doc.getSegmentAtAddress(ref_addr)
                    data_type = None
                    if ref_seg:
                        data_type = ref_seg.getTypeAtAddress(ref_addr)

                    if data_type is not None:
                        ref_info["type"] = Segment.stringForType(data_type)
         
                    direct_refs_from.append(ref_info)
            
            # Combine all reference information
            result["references"] = {
                "to_address": direct_refs_to,
                "from_address": direct_refs_from
            }
            
            results[address_or_name] = result
            
        except Exception as e:
            # Add error result for failed addresses
            error_result = {
                "queried_input": address_or_name,
                "error": str(e)
            }
            results[address_or_name] = error_result
    
    return results

@mcp.tool
def get_call_graph(
    start_addr_hex: Annotated[str, "Starting address for call graph generation as hex string"],
    direction: Annotated[str, "Direction to trace: 'forward' (callees), 'backward' (callers), or 'bidirectional'"] = "forward",
    max_depth: Annotated[int, Field(description="Maximum depth to traverse", ge=1, le=10)] = 2
) -> dict:
    """Return the call graph starting from a specific address.
    
    Creates a JSON representation of function call relationships, showing how
    functions call each other. Useful for understanding program flow and
    identifying critical code paths.
    
    WORKFLOW HINT: Use after identifying key functions with search_names_regex(),
    get_address_info(), decompile_procedure(), or disassemble_procedure(). Start with
    direction='forward' from main() or entry points to map program flow. Use 'backward'
    to find what calls a specific function of interest.
    """
    start_address = parse_hex_address(start_addr_hex)
    
    if direction not in ["forward", "backward", "bidirectional"]:
        raise ValueError("direction must be 'forward', 'backward', or 'bidirectional'")
    
    segment, procedure = get_segment_and_procedure(start_address)
    
    visited = set()
    call_graph = {
        "start_address": start_addr_hex,
        "direction": direction,
        "max_depth": max_depth,
        "nodes": {},
        "edges": []
    }

    def get_procedure_info(addr):
        """Get basic info about a procedure"""
        seg = doc.getSegmentAtAddress(addr)
        if not seg:
            return {"entry_point": f"0x{addr:x}",
                    "name": "unknown_segment"}
        proc = seg.getProcedureAtAddress(addr)
        if not proc:
            return {"entry_point": f"0x{addr:x}",
                    "name": "unknown_procedure"}

        proc_addr = proc.getEntryPoint()
        proc_name, demangled = get_procedure_names(seg, addr)
        
        ret = {
            "name": proc_name or f"unknown",
            "entry_point": f"0x{proc_addr:x}",
            "basic_blocks": proc.getBasicBlockCount()
        }

        if demangled != proc_name:
            ret["demangled_name"] = demangled
        signature = proc.signatureString()
        if signature:
            ret["signature"] = signature
        
        return ret
    
    def traverse_forward(addr, depth):
        """Traverse forward (callees)"""
        if depth >= max_depth:
            return

        # Add node info (even if already visited)
        node_info = get_procedure_info(addr)
        if node_info:
            call_graph["nodes"][f"0x{addr:x}"] = node_info
 
        seg = doc.getSegmentAtAddress(addr)
        if not seg:
            return
        
        proc = seg.getProcedureAtAddress(addr)
        if not proc:
            return

        name = get_procedure_name_with_fallback(addr)

        # Get callees
        callees = proc.getAllCallees()
        for callee in callees:
            to_addr = callee.toAddress()
            to_name = get_procedure_name_with_fallback(to_addr)
            
            # Always add edge (even to already visited nodes)
            call_graph["edges"].append({
                "from": name,
                "to": to_name
            })
            
            # Only recurse if not already visited (to prevent cycles)
            if to_addr not in visited:
                visited.add(to_addr)
                traverse_forward(to_addr, depth + 1)
    
    def traverse_backward(addr, depth):
        """Traverse backward (callers)"""
        if depth >= max_depth:
            return
 
        # Add node info (even if already visited)
        node_info = get_procedure_info(addr)
        if node_info:
            call_graph["nodes"][f"0x{addr:x}"] = node_info

        seg = doc.getSegmentAtAddress(addr)
        if not seg:
            return
 
        proc = seg.getProcedureAtAddress(addr)
        if not proc:
            return

        name = get_procedure_name_with_fallback(addr)

        # Get callers
        callers = proc.getAllCallers()
        for caller in callers:
            from_addr = caller.fromAddress()
            from_name = get_procedure_name_with_fallback(from_addr)
            
            # Always add edge (even to already visited nodes)
            call_graph["edges"].append({
                "from": from_name,
                "to": name
            })
            
            # Only recurse if not already visited (to prevent cycles)
            if from_addr not in visited:
                visited.add(from_addr)
                traverse_backward(from_addr, depth + 1)
    
    # Start traversal
    if direction == "forward":
        visited.add(start_address)
        traverse_forward(start_address, 0)
    elif direction == "backward":
        visited.add(start_address)
        traverse_backward(start_address, 0)
    elif direction == "bidirectional":
        visited.add(start_address)
        traverse_forward(start_address, 0)
        visited.clear()  # Reset for backward traversal
        visited.add(start_address)
        traverse_backward(start_address, 0)
    
    call_graph["total_nodes"] = len(call_graph["nodes"])
    call_graph["total_edges"] = len(call_graph["edges"])
    
    return call_graph

@mcp.tool
def decompile_procedure(
    address_or_name: Annotated[str, "The memory address as hex string (e.g., '0x1000') or procedure name"]
) -> str:
    """Decompile a procedure to C language code, making the function logic easier to
    understand than raw disassembly.
    
    Can accept either a hex address (starting with 0x) or a procedure name.
    """
    address = resolve_address_or_name_auto(address_or_name)
    segment, procedure = get_segment_and_procedure(address)
    
    # Get procedure information
    entry_point = procedure.getEntryPoint()
    signature = procedure.signatureString()
    regular_name, demangled_name = get_procedure_names(segment, entry_point)
    
    result = f"Procedure at 0x{entry_point:x}:\n"
    if regular_name:
        result += f"Name: {regular_name}\n"
    if demangled_name and demangled_name != regular_name:
        result += f"Demangled Name: {demangled_name}\n"
    if signature:
        result += f"Signature: {signature}\n"
    result += "\n"
    
    # Decompile the procedure
    decompiled = procedure.decompile()
    if decompiled:
        result += f"Decompiled code:\n{decompiled}"
    else:
        result += "Failed to decompile procedure"
    
    return result

@mcp.tool
def disassemble_procedure(
    address_or_name: Annotated[str, "The memory address as hex string (e.g., '0x1000') or procedure name"]
) -> str:
    """Disassemble a procedure into assembly language instructions.
    
    Can accept either a hex address (starting with 0x) or a procedure name.
    """
    address = resolve_address_or_name_auto(address_or_name)
    segment, procedure = get_segment_and_procedure(address)
    
    # Get procedure information
    entry_point = procedure.getEntryPoint()
    signature = procedure.signatureString()
    regular_name, demangled_name = get_procedure_names(segment, entry_point)
    
    result = f"Procedure at 0x{entry_point:x}:\n"
    if regular_name:
        result += f"Name: {regular_name}\n"
    if demangled_name and demangled_name != regular_name:
        result += f"Demangled Name: {demangled_name}\n"
    if signature:
        result += f"Signature: {signature}\n"
    result += f"Basic Blocks: {procedure.getBasicBlockCount()}\n"
    result += f"Heap Size: {procedure.getHeapSize()}\n\n"
    
    # Disassemble instruction by instruction with args and comments
    result += "Instructions:\n"
    for bb_index in range(procedure.getBasicBlockCount()):
        basic_block = procedure.getBasicBlock(bb_index)
        if basic_block:
            start_addr = basic_block.getStartingAddress()
            end_addr = basic_block.getEndingAddress()
            
            result += f"\nBasic Block {bb_index} (0x{start_addr:x} - 0x{end_addr:x}):\n"
            
            current_addr = start_addr
            while current_addr < end_addr:
                instruction = segment.getInstructionAtAddress(current_addr)
                if instruction:
                    instr_name = segment.getNameAtAddress(current_addr)
                    instr_comment = segment.getCommentAtAddress(current_addr)
                    
                    # Build instruction line with arguments
                    line = f"  0x{current_addr:x}: {instruction.getInstructionString()}"
                    
                    # Add formatted arguments if available
                    if instruction.getArgumentCount() > 0:
                        args = []
                        for i in range(instruction.getArgumentCount()):
                            formatted_arg = instruction.getFormattedArgument(i)
                            raw_arg = instruction.getRawArgument(i)
                            if formatted_arg and formatted_arg != raw_arg:
                                args.append(f"{formatted_arg}")
                            elif raw_arg:
                                args.append(raw_arg)
                        if args:
                            line += f" [{', '.join(args)}]"
                    
                    # Add name and comments
                    annotations = []
                    if instr_name:
                        annotations.append(f"name: {instr_name}")
                    if instr_comment:
                        annotations.append(f"comment: {instr_comment}")
                    
                    if annotations:
                        line += f" ; {' | '.join(annotations)}"
                    
                    result += line + "\n"
                    
                    current_addr += instruction.getInstructionLength()
                else:
                    current_addr += 1
    
    return result


@mcp.tool
def get_demangled_name(
    address_or_name: Annotated[str, "The memory address as hex string (e.g., '0x1000') or symbol name"]
) -> dict:
    """Get the demangled name at a specific address or for a given name.
    
    Demangling converts compiler-mangled symbol names (like C++ mangled names)
    back into their original, human-readable form for easier understanding.
    Can accept either a hex address (starting with 0x) or a symbol name.
    """
    address = resolve_address_or_name_auto(address_or_name)
    
    segment = doc.getSegmentAtAddress(address)
    if not segment:
        raise ValueError(f"No segment found at address 0x{address:x}")
    
    regular_name, demangled_name = get_procedure_names(segment, address)
    
    result = {
        "address": f"0x{address:x}",
        "demangled_name": demangled_name,
        "regular_name": regular_name,
        "has_demangled_name": bool(demangled_name and demangled_name != regular_name)
    }
    
    result["queried_input"] = address_or_name
    
    return result

@mcp.tool
def get_comment_at_address(address_hex: Annotated[str, "The memory address as hex string (e.g., '0x1000')"]) -> str:
    """Get the comment at a specific address.
    
    Comments are user or automatically generated annotations attached to
    specific addresses to document code behavior or analysis findings.
    """
    address = parse_hex_address(address_hex)
    segment = doc.getSegmentAtAddress(address)
    if not segment:
        raise ValueError(f"No segment found at address 0x{address:x}")
    
    comment = segment.getCommentAtAddress(address)
    if comment:
        return f"Comment at 0x{address:x}: {comment}"
    else:
        return f"No comment found at address 0x{address:x}"

@mcp.tool
def set_comment_at_address(
    address_hex: Annotated[str, "The memory address as hex string (e.g., '0x1000')"],
    comment: Annotated[str, "The comment text to set at the address"]
) -> str:
    """Set a comment at a specific address.
    
    Adds or updates a text comment annotation at a memory address for
    documentation purposes. Changes are saved to the document.
    """
    address = parse_hex_address(address_hex)
    segment = doc.getSegmentAtAddress(address)
    if not segment:
        raise ValueError(f"No segment found at address 0x{address:x}")
    
    success = segment.setCommentAtAddress(address, comment)
    if success:
        doc.saveDocument()
        return f"Successfully set comment at address 0x{address:x}"
    else:
        return f"Failed to set comment at address 0x{address:x}"

@mcp.tool
def set_name_at_address(
    address_hex: Annotated[str, "The memory address as hex string (e.g., '0x1000')"],
    name: Annotated[str, "The name/label to set at the address"]
) -> str:
    """Set a name/label at a specific address.
    
    Assigns a human-readable identifier to a memory address for easier
    reference and analysis. Changes are saved to the document.
    """
    address = parse_hex_address(address_hex)
    success = doc.setNameAtAddress(address, name)
    if success:
        doc.saveDocument()
        return f"Successfully set name '{name}' at address 0x{address:x}"
    else:
        return f"Failed to set name '{name}' at address 0x{address:x}"

@mcp.tool
def mark_data_type_at_address(
    address_hex: Annotated[str, "The address to mark as hex string (e.g., '0x1000')"],
    data_type: Annotated[str, "Type to mark: 'code', 'procedure', 'int8', 'int16', 'int32', 'int64', 'ascii', 'unicode', 'undefined', 'byte_array', 'short_array', 'int_array'"],
    length: Annotated[int, Field(description="Length for data types", ge=1)] = 1
) -> str:
    """Mark data type at a specific address.
    
    Tells the disassembler how to interpret the bytes at an address - as code,
    data types (integers, strings), or arrays. This affects analysis and display.
    """
    address = parse_hex_address(address_hex)
    
    segment = doc.getSegmentAtAddress(address)
    if not segment:
        raise ValueError(f"No segment found at address 0x{address:x}")
    
    success = False
    
    if data_type.lower() == 'code':
        success = segment.markAsCode(address)
    elif data_type.lower() == 'procedure':
        success = segment.markAsProcedure(address)
    elif data_type.lower() == 'undefined':
        if length > 1:
            success = segment.markRangeAsUndefined(address, length)
        else:
            success = segment.markAsUndefined(address)
    elif data_type.lower() == 'int8':
        success = segment.setTypeAtAddress(address, length, Segment.TYPE_INT8)
    elif data_type.lower() == 'int16':
        success = segment.setTypeAtAddress(address, length, Segment.TYPE_INT16)
    elif data_type.lower() == 'int32':
        success = segment.setTypeAtAddress(address, length, Segment.TYPE_INT32)
    elif data_type.lower() == 'int64':
        success = segment.setTypeAtAddress(address, length, Segment.TYPE_INT64)
    elif data_type.lower() == 'ascii':
        success = segment.setTypeAtAddress(address, length, Segment.TYPE_ASCII)
    elif data_type.lower() == 'unicode':
        success = segment.setTypeAtAddress(address, length, Segment.TYPE_UNICODE)
    elif data_type.lower() == 'byte_array':
        success = segment.markAsDataByteArray(address, length)
    elif data_type.lower() == 'short_array':
        success = segment.markAsDataShortArray(address, length)
    elif data_type.lower() == 'int_array':
        success = segment.markAsDataIntArray(address, length)
    else:
        raise ValueError(f"Unknown data type '{data_type}'. Valid types: code, procedure, int8, int16, int32, int64, ascii, unicode, undefined, byte_array, short_array, int_array")
    
    if success:
        doc.saveDocument()
        return f"Successfully marked address 0x{address:x} as {data_type} (length: {length})"
    else:
        return f"Failed to mark address 0x{address:x} as {data_type}"

################################ MCP REQUEST RUNNER ############################

def _json_dump_atomic(path, payload):
    tmp_path = f"{path}.tmp.{os.getpid()}"
    with open(tmp_path, "w", encoding="utf-8") as output_file:
        json.dump(payload, output_file, default=str)
    os.replace(tmp_path, path)

def _request_id_from_path(path, suffix):
    name = os.path.basename(path)
    if not name.endswith(suffix):
        return None
    return name[:-len(suffix)]

def _claim_next_request():
    os.makedirs(REQUEST_DIR, exist_ok=True)
    request_names = sorted(
        name for name in os.listdir(REQUEST_DIR)
        if name.endswith(REQUEST_SUFFIX)
    )
    for request_name in request_names:
        request_id = _request_id_from_path(request_name, REQUEST_SUFFIX)
        if not request_id:
            continue
        request_path = os.path.join(REQUEST_DIR, request_name)
        running_path = os.path.join(REQUEST_DIR, f"{request_id}{RUNNING_SUFFIX}")
        try:
            os.replace(request_path, running_path)
            return request_id, running_path
        except OSError:
            continue
    return None, None

def run_pending_request_once():
    if not IN_HOPPER:
        raise RuntimeError("run_pending_request_once() must be run inside Hopper")

    request_id, running_path = _claim_next_request()
    if not request_id:
        message = f"No pending Hopper MCP request in {REQUEST_DIR}"
        print(message)
        _log(message)
        return message

    response_path = os.path.join(REQUEST_DIR, f"{request_id}{RESPONSE_SUFFIX}")
    _log(f"processing request_id={request_id}")

    try:
        with open(running_path, "r", encoding="utf-8") as input_file:
            request = json.load(input_file)
        tool_name = request.get("tool")
        args = request.get("args") or {}
        if tool_name == "__ping__":
            result = {
                "name": mcp.name,
                "tools": sorted(mcp.tools.keys()),
                "document": doc.getDocumentName(),
            }
        else:
            if tool_name not in mcp.tools:
                raise ValueError(f"Unknown tool '{tool_name}'")
            if not isinstance(args, dict):
                raise ValueError("Tool args must be an object")
            result = mcp.tools[tool_name](**args)
        _json_dump_atomic(response_path, {
            "ok": True,
            "id": request_id,
            "result": result,
        })
        _log(f"completed request_id={request_id} tool={tool_name}")
        print(f"Hopper MCP request complete: {tool_name}")
        return result
    except Exception as exc:
        error_text = traceback.format_exc()
        _json_dump_atomic(response_path, {
            "ok": False,
            "id": request_id,
            "error": str(exc),
            "traceback": error_text,
        })
        _log(f"failed request_id={request_id}\n{error_text}")
        try:
            doc.log(error_text)
        except Exception:
            pass
        raise
    finally:
        try:
            os.remove(running_path)
        except OSError:
            pass

def start_hopper_mcp():
    return run_pending_request_once()

def cache_strings():
    print("Starting caching...")
    if create_string_caches_for_all_documents():
        print("Caching complete!")
        print("String search cache is ready for Hopper MCP requests.")
    else:
        print("String caching failed! Try saving all documents and pasting this again:")
        print("cache_strings()")

if IN_HOPPER:
    try:
        _log("entered Hopper auto-start block")
        if not check_all_documents_have_string_caches():
            print("Due to slow Hopper string APIs, we must create our own string caches.")
            print("This process will take about 5-10 minutes per document and will save caches along side your hopper document saves.")
            print("\nTo start this process now, run this in the Python prompt when convenient:")
            print("cache_strings()")
            print("\nRunning one Hopper MCP request now. String searches may be slow.")
        else:
            print("Congratulations! We found cached strings for your documents. The search_strings_regex() tool should now be FAST!")
        run_pending_request_once()
    except Exception:
        error_text = traceback.format_exc()
        _log(error_text)
        try:
            doc.log(error_text)
        except Exception:
            pass
        raise
