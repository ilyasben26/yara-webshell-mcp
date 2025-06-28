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



@mcp.prompt
def generate_yara_rule(filepath: str) -> str:
    """Generate a prompt that guides the LLM to analyze a file and create a YARA rule."""
    return f"""You are a malware analyst.

Your task is to create a YARA rule for the file located at: {filepath}

## Workflow:
1. Use the MCP tool `tools()` to discover which analysis tools are available.
2. Based on the available tools, select and use the ones that help you analyze the file. This may include:
    - Extracting strings.
    - Getting file metadata or hashes.
    - Checking entropy or file type.
    - Any other relevant analysis tools listed.
3. Use the insights from your analysis to generate an effective YARA rule that detects this file based on its unique characteristics.
4. Save the YARA rule as a `.yar` file into the folder `yara-rules/`. If the folder doesn't exist, then create it. Use the original filename (without extension) as the rule file name.

## Notes:
- The YARA rule should include meaningful strings, conditions, and metadata if applicable.
- Avoid overfitting; the rule should not match clean files unnecessarily.
- Confirm the rule has been saved.

Start by running the `tools()` command to check which tools are available."""


if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='stdio')