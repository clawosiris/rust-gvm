![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

# Community container tests

Add basic community container tests.

Currently the base test runs a "All IANA assigned TCP"
 port test against a test server
 and checks if the scan task ends with "DONE"
 otherwise the workflow fails.
 The log file from gvmd, ospd, openvas and gsad are always printed.

## test-community-docker.gmp.py

### Options

```
-h, --help show this help message and exit
--hosts HOSTS [HOSTS ...]
Hosts to scan e.g IP/SUBNET
--target-name TARGET_NAME
Target name to use and or create e.g "TestTarget"
--no-target-create Do not create the target, otherwise it needs to exist, default False
--task-name TASK_NAME
Task name to use andor create e.g "TestTask"
--no-task-create Do not create the task, otherwise it needs to exist, default False
--port-list PORT_LIST
Port list as name to use with the task e.g "All IANA assigned TCP"
--scan-config SCAN_CONFIG
Scan config as name to use with the task e.g "Full and fast"
--scanner SCANNER Scanner as name to use with the task e.g "OpenVAS Default"
```
