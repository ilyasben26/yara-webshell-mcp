import subprocess
import json
from mcp.server.fastmcp import FastMCP
import os
import platform

# Initialize FastMCP server
mcp = FastMCP("yara-webshell")


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FOLDER = os.path.join(SCRIPT_DIR, "data")
# Ensure the data folder exists
if not os.path.exists(DATA_FOLDER):
    os.makedirs(DATA_FOLDER)
BINARIES_FOLDER = os.path.join(SCRIPT_DIR, "binaries")
IS_WINDOWS = platform.system() == "Windows"

@mcp.tool()
async def run(command: str) -> str:
    """Run a shell command and return output as a JSON string.

    Args:
        command (str): Shell command to execute.

    Returns:
        str: JSON string with stdout, stderr, exit_code, and command.
    """
    # TODO: sanitize the input

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=True,  # Safe as long as only trusted input is used
            cwd=DATA_FOLDER
        )

        output = {
            "command": command,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "exit_code": result.returncode
        }

    except Exception as e:
        output = {
            "command": command,
            "stdout": "",
            "stderr": str(e),
            "exit_code": -1
        }

    return json.dumps(output, indent=2)


@mcp.tool()
async def tools() -> dict:
    """List available malware analysis and utility tools."""
    if IS_WINDOWS:
        tools_dict = {
            "findstr": {
                "description": "Search for patterns in files (Windows equivalent of grep).",
                "usage": "findstr pattern filename",
                "help": "findstr /?"
            },
            "type": {
                "description": "Display file content (Windows equivalent of cat).",
                "usage": "type filename",
                "help": "type /?"
            },
            "floss": {
                "description": "Extract strings from malware samples.",
                "usage": "floss.exe filename",
                "help": "floss.exe --help",
                "location": f"{os.path.join(BINARIES_FOLDER, 'floss.exe')}"
            },
            "yara": {
                "description": "Scan files with YARA rules.",
                "usage": "yara64.exe rules.yar filename",
                "help": "yara64.exe --help",
                "location": f"{os.path.join(BINARIES_FOLDER, 'yara64.exe')}"
            },
            # Add more Windows tools as needed
        }
        # Optionally add 'strings.exe' if available
        strings_path = os.path.join(BINARIES_FOLDER, 'strings.exe')
        if os.path.exists(strings_path):
            tools_dict["strings"] = {
                "description": "Extract printable strings from binary files.",
                "usage": "strings.exe [options] filename",
                "help": "strings.exe /?"
            }

    else:
        tools_dict = {
            "file": {
                "description": "Identify file type using magic bytes.",
                "usage": "file filename",
                "help": "file --help"
            },
            "yara": {
                "description": "Scan files with YARA rules.",
                "usage": "yara rules.yar filename",
                "help": "yara --help"
            },
            "strings": {
                "description": "Extract printable strings from binary files.",
                "usage": "strings [options] filename",
                "help": "man strings"
            },
            "grep": {
                "description": "Search for patterns in files.",
                "usage": "grep 'pattern' filename",
                "help": "man grep"
            },
            "sed": {
                "description": "Stream editor for filtering and transforming text.",
                "usage": "sed 's/old/new/g' filename",
                "help": "man sed"
            },
            "cat": {
                "description": "Concatenate and display file content.",
                "usage": "cat filename",
                "help": "man cat"
            },
            "floss": {
                "description": "Extract strings from malware samples.",
                "usage": "floss filename",
                "help": "floss --help",
                "location": f"{os.path.join(BINARIES_FOLDER, f'floss')}"
            },
            # Add more tools as needed
        }
    return {"tools": tools_dict}


@mcp.prompt()
def generate_yara_rule(filepath: str) -> str:
    """Generate a prompt that guides the LLM to analyze a file and create a YARA rule."""
    os_name = platform.system()
    if os_name == "Windows":
        yara_folder = r"%USERPROFILE%\yara-rules"
    return f"""You are a malware analyst.

Your task is to create a YARA rule for the file located at: {filepath}

## Environment:
- The operating system is: {os_name}

## Workflow:
1. Use the MCP tool `tools()` to discover which analysis tools are available. You have access to a shell using the MCP tool `run()`.
2. Based on the available tools, select and use those that help you analyze the file. This may include:
    - Extracting strings.
    - Getting file metadata or hashes.
    - Checking entropy or file type.
    - Any other relevant analysis tools listed.
3. Use the insights from your analysis to generate a YARA rule that detects this file based on its unique and distinguishing characteristics, but ensure the rule is general enough to match similar malware samples, not just this exact file.
4. Avoid using file hashes or overly specific values that would only match this single file. Prefer patterns, strings, or structural features that are likely to be shared by related malware.
5. Save the YARA rule as a `.yar` file into the folder `{"%USERPROFILE%\\yara-rules" if os_name == "Windows" else "$HOME/yara-rules"}`. If the folder doesn't exist, then create it. Use the original filename (without extension) as the rule file name.

## Notes:
- The YARA rule should include meaningful strings, conditions, and metadata if applicable.
- Avoid overfitting; the rule should not match clean files unnecessarily, nor should it be so specific that it only matches this single file.
- Confirm the rule has been saved.

Start by running the `tools()` command to check which tools are available. You don't have to use all tools, just the ones that are relevant for your analysis.
At the end, make sure to show the generated YARA rule in the response."""


if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='stdio')