# LAN source readback — partial with original admission timeout

The first three fixed source files are fully recovered and match the frozen whole bytes. Source 3's independent file metadata is also complete and inactive and matches the original receipt's identity. The sole source 3 first-block operation_start returned MCP -32603 timeout without an ACK or operation ID. Its raw SDK and exact typed request are preserved before any interpretation.

No subsequent source block or file was admitted, and no read or business process was replayed. There are zero tool calls in flight, but the unknown native future is not claimed inactive or unstarted. Three whole sources remain qualified only within their observed scope; the remaining six are not implied complete. The original inert job's known exit 0 and historical start timeout are unchanged.
