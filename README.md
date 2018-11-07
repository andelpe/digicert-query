digicert-query
==============
Python-based command line utility to query Digicert's REST service (based on digicert_client python API)

Important notes
---------------

DigiCert API does not support Python 3. Please, use Python 2.

You may need to apply Pull \#2 to digicert\_client after install
(<https://github.com/digicert/digicert_client/pull/2>)

Basics
-------

You can perform a single type of query by selecting only one of the main
options:

    --me
    --list
    --show
    --down
    --new
    --renew 

For every query, you need to specify your DigiCert API key for
authentication, either by using `-k` option or by specifying it
interactively.

Some queries (`--me/--list`) need no additional information, while
others (`--show/--down/--renew`) require that an order ID is specified
as well (with `--id`).

Certificate request
-------------------
A new cert can be requested (`--new`) or one renewed (`--renew`). For
the moment, only host certificates are supported.

For certificate request, some input information is required. This
information is either passed with a configuration file (`--conf`), or
defaults may be used. The only parameter that is always required is the
hostname (may be set directly with `--hname`).

The defaults are obtained from a file called
`/root/.dgc-query.defaults`. (may be overriden with `--defaults`
option). The file must contain a json-formatted dictionary of parameters
(any parameter starting with `__` will be ignored). Please use
`--params` for parameters typically used in the defaults file.

> Note: please see file `template.defaults` for an example of how the
> file should look like.

The only always-required parameter (no default is accepted) is the
hostname for the cert. You may use the `--hname` option to provide it
(or include in the config file with `--conf`). The config file may also
override defaults, or specify other optional parameters. The format is
the following:

    [params]
    <param1>: <value1>
    <param2>: <value2>
    ...

The leading `[params]` is literal, the rest must be replaced by real
param names.

Note that the request requires a CSR file, which, if not provided
explicitely (`--csr`), is generated using the defaults/config file
parameters, and the system's default openssl values.

To see the complete list of default/optional parameters, use option
`--params`.

### Special considerations for Multi Domain certificate

If you want to order a GRID Host SSL Multi Domain cert, you probably
want to use `--alt` option to provide a list of comma-separated names to
be included in the SAN field (in addition to that specified as
`hostname`).

Behind the scenes, this creates a temporary openssl conf file, based on
system's default (/etc/pki/tls/openssl.cnf), but with the addition of
the alt names, to generate the CSR file. One may customize this by
setting his own SSL config file (`--ssl-conf`), or directly providing
its own CSR file (`--csr`).

An alternative to using the `--alt` option is to manually include
parameters `certificate_type` and `sans` in the file passed to `--conf`
(in that case, you also need to use `--ssl-conf`).

Examples
--------

-   List existing orders (API key will be asked interactively):

        dgc-query.py --list

-   List 50 (max) orders, skipping the first 100:

        dgc-query.py -k api.key --list --off 100 --lim 50

-   Show details of request with order ID 345:

        dgc-query.py -k api.key --show --id 345

-   Ask for a new certificate (returns associated order ID):

        dgc-query.py -k api.key --new --hname myhost.ciemat.es

-   Ask for a new certificate with additional hostnames:

        dgc-query.py -k api.key --new --hname myalias.ciemat.es --alt myhost1.ciemat.es,myhost2.ciemat.es

-   Download certificate with order ID 345:

        dgc-query.py -k api.key --down --id 345

-   Ask for a new certificate with additional configuration:

        dgc-query.py -k api.key --renew --hname myhost.ciemat.es --conf myconf.file

-   Renew certificate with order ID 345:

        dgc-query.py -k api.key --renew --hname myhost.ciemat.es --id 345

Command Usage
-------------
For up-to-date information, please run `dgc-query.py -h`.

Usage:

    dgc-query.py [-h] [--version] [-v] [--dry] [-u] [-k KEY]
                 [-m | -l | -s | -d | -n | -r] [--params] [--id ID]
                 [--defaults DEFAULTS] [--conf CONF] [--hname HNAME]
                 [-c CSR] [--alt ALTNAMES] [--ssl-conf SSLCONF]
                 [--limit LIMIT] [--offset OFFSET]

Optional arguments:

    -h, --help           show this help message and exit
    --version            show program's version number and exit
    -v, --verbose        Be verbose (show additional information). Use twice for extra verbose.
    --dry                Do not send request, generate request object and show it.
    -u, --usage          Show usage information
    -k KEY, --key KEY    Get API key from file (otherwise it's asked interactively).
    -m, --me             Show information about me
    -l, --list           List certificate orders
    -s, --show           Show details about specified (id) order (usually, a cert request). Requires --id.
    -d, --download       Download specified (order id) certificate. Requires --id.
    -n, --new            Request a new certificate. Requires --conf and/or --hname.
    -r, --renew          Renew an existing certificate. Requires --id.
    --params             Show default/opt params for cert request conf file (no DigiCert query is sent).
    --id ID              For -s/-d: specify order ID for request to query/cert to download.
    --defaults DEFAULTS  For cert request: set defaults file (default: /root/.dgc-query.defaults)
    --conf CONF          For cert request: set config file
    --hname HNAME        For cert request: set param 'hostname' (overrides conf file).
    -c CSR, --csr CSR    For cert request: get CSR from file 'csr' (otherwise generate from conf values).
    --alt ALTNAMES       For cert request: set additional hostnames (comma-separated) to be secured (SAN list).
    --ssl-conf SSLCONF   For cert request: use specified openssl conf file.
    --limit LIMIT        For order list: set responses limit (default: 1000).
    --offset OFFSET      For order list: set skip offset (of own orders).

References
----------

-   REST API doc: <https://www.digicert.com/services/v2/documentation>
-   Python client: <https://pypi.org/project/digicert_client>
