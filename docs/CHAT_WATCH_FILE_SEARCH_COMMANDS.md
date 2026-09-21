# Chat Watch, File Search, and Command Execution

UPAB now defines three distinct capabilities:

## Chat/message watching

`ChatMessageWatcher` watches a supported authorized `MessageSource` and emits each new message once.

This is a transport abstraction. It does not scrape ChatGPT browser state, cookies, credentials, or undocumented private endpoints. A supported source adapter must be supplied separately.

## File search

`search_files` searches configured filesystem roots by filename while skipping inaccessible paths. Search roots must be explicitly configured by the operator. This allows UPAB to locate project files without guessing paths.

## PowerShell execution

Existing `ToolExecutor.run_powershell` remains the execution boundary.

Commands should pass PowerShell preflight before execution, including:
- executable availability;
- repository/target-path containment;
- target resolution;
- syntax/parse validation when the host adapter supports it;
- expected side effects;
- postcondition verification.

Watching a chat never by itself authorizes command execution. A watched message may be converted into a proposed relay task, but governance and authorization still decide whether the command can run.
