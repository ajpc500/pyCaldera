# pyCaldera

A basic python API library for [MITRE Caldera](https://caldera.mitre.org). 

Functionality is implemented to interact with data types as follows:

| Data Type        | Functionality                       |
|------------------|-------------------------------------|
| Server Health    | ✅ Fetch                            |
| Plugins          | ✅ Fetch                            |
| Operations       | ✅ Fetch                            |
|                  | ✅ Create                           |
|                  | 🔴 Delete                           |
|                  | 🔴 Edit                             |
| Agents           | ✅ Fetch                            |
|                  | ✅ Update                           |
| Links            | ✅ Fetch                            |
| Abilities        | ✅ Fetch                            |
|                  | ✅ Create                           |
|                  | ✅ Execute (via Access plugin)      |
|                  | 🔴 Delete                           |
|                  | 🔴 Edit                             |
| Adv. Profiles    | ✅ Fetch                            |
|                  | ✅ Create                           |
|                  | 🔴 Delete                           |
|                  | 🔴 Edit                             |
| Exfil File       | ✅ Create                           |



## TODO:

- [ ] Improved error handling for API authentication.
- [ ] Fetching of fact sources, parsers, etc. to better tailor operation configuration.
- [ ] Filtering of results and table creation
