segway - Testing framework for IPv6 segment routing on Linux

segway sets up a network namespace with special network interfaces, simulating an IPv6 network with Segment Routing, and executes a given test suite, sending and sniffing packets. An example of test suite is provideed in [tests/example.seg](tests/example.seg).

segways uses Python 2.7 and requires several dependencies, which can be installed using [pipenv](https://docs.pipenv.org/).

```
git clone https://github.com/Zashas/segway.git
pipenv install
pipenv shell
cd segway
sudo python segway.py tests/example.seg
```

=== Usage ===

```
Usage:
    segway.py <path_to_tests> [--ns=<ns_name>] [-k] [-r] [-p]
    segway.py (-h | --help)

Options:
    -h, --help  Show help
    --ns=<ns_name>  Use specific network space name
    -k              Keep network namespace after running tests
    -r              Reuse network namespace and interfaces
    -p              Show packets of passed tests
```
