# ISSUE CONTRACT
## Pain
Edge handlers inherit broad env privileges; tokens not bound to request body.
## Success
- Token bound to body digest + path
- Expiry enforced
- Replay on different body refuses
