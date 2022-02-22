# Fail2Ban Service
Simple modular centralized fail2ban clone

## API
This section lists all provided endpoints

| Endpoint | Purpose | Method | Notes | Expected body |  
| --- | --- | --- | --- | --- |
| /api/policy | Show active policy | GET | Both durations are in nanoseconds  
| /api/policy | Update active policy | PATCH | Both durations are in nanoseconds | `{"attempts": <int>, "period": <int>, "blocktime": <int>}` 
| /api/blocked/{ip} | Check if IP is blocked | GET | Will also return a block entry if applicable: `{"blocked": true, "entry": {"source": <string>, "timestamp": <int>, "duration": <int>}}`
| /api/block/{ip} | Block given IP | POST | Active policy is used to determine time blocked
| /api/unblock/{ip} | Unblock given IP | POST | Returns error if IP is not blocked
| /api/entries | Show all IPs with amounts of failed attempts | GET | Returns a map/object where every key is the source and the int value the amount of attempts
| /api/entries/list/{ip} | Show all attempts of IP | GET | Timestamp is in unix time
| /api/entries/add/{ip} | Add new attempt for IP | PUT | Service must be set. Entry will not be added if IP is already blocked | `{"source": <string>, "service": <string>, "timestamp": <int>}`