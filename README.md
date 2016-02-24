# resolve.py

Performs an iterative resolution of a DNS name, type, class, starting from the root DNS servers.

Modified so that it could easily be used from within Python scripts.

Original Author: Shumon Huque

Modified by: John Lawrence M. Penafiel

See the original project at https://github.com/shuque/resolve

## Usage
```
import resolve

# create sample callback function
def callback(zones):
  # print nameservers
  for nameservers in zones:
    for nameserver in nameservers:
      print nameserver
  # return True to break from the resolution process
  return False

# invoke resolve
resolve.resolve('example.com', timeout=3, callback=callback)
```
