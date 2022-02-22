# Fail2Ban Service
Simple modular centralized fail2ban clone

## API
This section lists all provided endpoints

| Endpoint | Purpose | Method | Notes | Expected body |  
| --- | --- | --- | --- | --- |
| /api/policy | Show active policy | GET | Both durations are in nanoseconds  
| /api/policy | Update active policy | PATCH | Both durations are in nanoseconds. Policy will not be applied retroactively | `{"attempts": <int>, "period": <int>, "blocktime": <int>}` 
| /api/blocked/{ip} | Check if IP is blocked | GET | Will also return a block entry if applicable: `{"blocked": true, "entry": {"source": <string>, "timestamp": <int>, "duration": <int>}}`
| /api/block/{ip} | Block given IP | POST | Active policy is used to determine time blocked
| /api/unblock/{ip} | Unblock given IP | POST | Returns error if IP is not blocked
| /api/entries | Show all IPs with amounts of failed attempts | GET | Returns a map/object where every key is the source and the int value the amount of attempts
| /api/entries/list/{ip} | Show all attempts of IP | GET | Timestamp is in unix time
| /api/entries/add/{ip} | Add new attempt for IP | PUT | Service must be set. Entry will not be added if IP is already blocked | `{"source": <string>, "service": <string>, "timestamp": <int>}`
| /api/modules | Show all active external modules | GET | Will return an array of all active modules: `{"id": <uint32>, "address": <string>, "method": <string>}`
| /api/module | Add new external module | PUT | The server will make a HTTP request to the given address using the given module. The body will be as described in the [external module section](external-modules) | `{"address": <string>, "method": <string>}`
| /api/module/{id} | Deletes the external module with the given ID | DELETE | The ID is returned at module creation, and when listing all modules

## External modules
Besides the `/api/blocked/{ip}` route, the server can also notify external modules of changes in block state. 
As mentioned in the [API section](#api) the server will make HTTP requests to external modules, using the given address and HTTP method.
The body will contain a JSON object, which embeds the relevant block entry and an additional boolean indicating whether this 
blocks or unblocks the given source. The structure of the object is as follows:
```
{
  "source": <string>,
  "timestamp": <int>,
  "duration": <int>,
  "blocked": <bool>
}
```
As with all other objects used the timestamp is an integer representing the unix time, and the duration is an integer 
representing duration in nanoseconds. Note that a negative (or zero) duration effectively means the given source/IP has
to be unblocked. An additional boolean is added to make it more clear when the source/IP needs to be blocked or unblocked.

Example request of a block event:
```json
{
  "source": "10.42.42.42",
  "timestamp": 1645545564,
  "duration": 60000000000,
  "blocked": true
}
```

Example request of an unblock event:
```json
{
  "source": "10.42.42.42",
  "timestamp": 1645545615,
  "duration": -60000000000,
  "blocked": false
}
```