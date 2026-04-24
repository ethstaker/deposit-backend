# deposit-backend

This project serves as a backend for a to-be-created launchpad alternative.

It simply provides the frontend with beacon chain data and withdrawal_address->validator mappings.

# Usage
```
Usage of ./deposit-backend:
  -beacon-url value
        The beacon URL to use. May be repeated.
  -host string
        The host to listen on (default "127.0.0.1")
  -log-format value
        The log format to use - 'text' or 'json'
  -log-level value
        The log level to use
  -port int
        The port to listen on (default 8080)
  -refreshInterval uint
        How many slots to wait between refreshes of the index (default 4)
```

# License
[AGPLv3](./LICENSE)
