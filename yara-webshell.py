import subprocess
import json
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("yara-webshell")

DATA_FOLDER = "data/"

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

if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='stdio')