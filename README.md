# YARA-WEBSHELL-MCP

## TO-DO:

- Implement /run endpoint
  - Prompt the user to install the tool in case it doesn't exist on the system?
- Implement /tools endpoint
  - Verify if tool is installed on the system as well?

| Endpoint  | Purpose                                  |
| --------- | ---------------------------------------- |
| `/run`    | Run a command/tool                       |
| `/tools`  | List available tools with descriptions   |
| `/status` | Check job status (if async)              |
| `/logs`   | Retrieve logs or recent executions       |
| `/files`  | List available files in workspace folder |

# Endpoints specifications

## run

Input:

```json
{
  "command": "yara rules.yar /data/filexyz.exe"
}
```

Output:

```json
{
  "stdout": "YARA match: malware_rule",
  "stderr": "",
  "exit_code": 0
}
```

## tools

Output:

```json
{
  "tools": {
    "file": {
      "description": "Identify file type using magic bytes.",
      "usage": "file filename",
      "help": "files --help"
    },
    "yara": {
      "description": "Scan files with YARA rules.",
      "usage": "yara rules.yar filename",
      "help": "yara --help"
    },
    "strings": {
      "description": "Extract printable strings from binary files.",
      "usage": "strings [options] filename"
    },
    "capa": {
      "description": "Detect malware capabilities in executables.",
      "usage": "capa filename"
    },
    "grep",
    "sed",
    "cat",
    ...
  }
}
```

## files

Input:

```json
{
  "regex_query": ""
}
```

Output

```json
{
  "files": ["filexyz.exe", "webshell.php", "rules.yar"]
}
```
