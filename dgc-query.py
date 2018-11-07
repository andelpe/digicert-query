#!/usr/bin/env python2

#
# Written by: Antonio Delgado Peris (antonio.delgadoperis@ciemat.es)
# Institute:  CIEMAT (Madrid, Spain)
#

####   IMPORTS   ####
from __future__ import print_function, division
import os, sys
from utils import err, shell
from ConfigParser import ConfigParser
from argparse import ArgumentParser, Action, RawTextHelpFormatter
import digicert_client.api as dgc
from getpass import getpass
from pprint import pprint
import socket
import tempfile
import json


####   CONSTANTS   ####
DGC_HOST = 'www.digicert.com'
qapi = dgc.queries.v2
capi = dgc.commands.v2

CERT_TYPES = ['grid_host_ssl', 'grid_host_ssl_multi_domain']
GEN_CSR_CMD  = 'openssl req -new -newkey rsa:2048 -nodes -out {hname}.csr -keyout {hname}.key -subj "{subject}"'
SHOW_CSR_CMD = 'openssl req -in {csrFile} -noout -text'
OPENSSL_CONF = '/etc/pki/tls/openssl.cnf'
DEFAULTS_FILE = os.environ['HOME'] + '/.dgc-query.defaults'

defaultAttrs = [
    'validity',
    'certificate_type',
    'organization_units',
    'server_platform',
    'organization_id',
    'signature_hash',
    'sans',
    'subject',
    'auto_renew',
]

reqParams = (
    'hostname',
)

moreParams = (
    'common_name  (by default, uses "hostname")',
    'csr     (usually generated with system defaults, or set by command options)',
    'server_type',
    'custom_expiration_date',
    'comments',
    'telephone',
    'org_contact_job_title',
    'org_contact_telephone_ext',
    'service_name',
    'org_name',
    'org_name',
    'org_city',
    'org_state',
    'org_country',
    'org_addr1',
    'org_addr2',
    'org_zip',
    'org_contact_firstname',
    'org_contact_lastname',
    'org_contact_email',
    'org_contact_telephone',
)
#    'org_unit',


####   FUNCTIONS   ####

def printj(x, stream=None):
    """
    Print json object with nice indentation.
    The 'stream' arg may be used to print to other than stdout (e.g. stderr).
    """
    if stream:  print(json.dumps(x, indent=3), file=stream)
    else:       print(json.dumps(x, indent=3))


def buildOpensslConfFile(tempSslConf, names):
    """
    Build a temp openssl config file, including specified alternative names (SAN list).
    We just add a few lines to system's default conf file.

    If you don't like this, use --ssl-conf !!
    """
    with open(OPENSSL_CONF) as f1, open(tempSslConf, 'w') as f2:

        for line in f1:
            f2.write(line)

            if line.startswith('[ req ]'):    
                f2.write('req_extensions = v3_req\n')

            if line.startswith('[ v3_req ]'): 
                f2.write('subjectAltName = @alt_names\n')

        f2.write('[alt_names]\n')
        for i, name in enumerate(names):
            f2.write('DNS.{i} = {name}\n'.format(i=i+1, name=name))


def prepareParams(args, defaults, renew=False):
    """
    For certificate requests, build the params dictionary using specified hostname or
    configuration file.
    """

    mydomain = socket.getfqdn().split('.',1)[1]

    # Initialize 'params' with defaults (may be overriden)
    params = defaults

    # Either used passed hostname or read properties from file (or both)
    passedArgs = []
    if args.conf:
        cfg = ConfigParser()
        cfg.read(args.conf)
        passedArgs = dict(cfg.items('params'))
        params.update(passedArgs)

    # If this is a renewal, need to include the order id of the cert being renewed
    if renew:  params['renewal_of_order_id'] = args.id

    # Check --hname option
    if args.hname:
        if not '.' in args.hname: 
            params['hostname'] = args.hname.strip() + '.' + mydomain
        else:
            params['hostname'] = args.hname.strip()

    # Check --altNames option (first time)
    if args.altNames:
        params['certificate_type'] = CERT_TYPES[1]
        params['sans'] = args.altNames

    # Sanitize SANs (no matter if coming from --altNames or conf file)
    if params['sans']:
        sans = []
        for host in params['sans'].split(','):
            if not '.' in host:  sans.append(host + '.' + mydomain)
            else:                sans.append(host)
        params['sans'] = sans

    # Validate params included in our list
    for param in reqParams:
        if param not in params: 
            err('Required parameter {} not in conf file'.format(param))
            return 11
    
    # If not manually passed, create CSR
    if 'csr' not in passedArgs:

        if args.csr:
            csrFile = args.csr

        else:
            if args.verb:  err('\n-- CSR not specified, generating one with openssl.')

            if args.sslConf:  
                # If a custom openssl conf file is passed, just use it
                genCmd = GEN_CSR_CMD + ' -config {}'.format(args.sslConf)

            else:             
                    # If alt names are added, we need to build a special openssl conf file
                if args.altNames:
                    tempSslConf = tempfile.mkstemp()[1]
                    buildOpensslConfFile(tempSslConf, [params['hostname']]+params['sans'])
                    #
                    # Now, set -config with written temp file
                    genCmd = GEN_CSR_CMD + ' -config {}'.format(tempSslConf)

                # Normal case, we just avoid -config option (openssl will use defaults)
                else:
                    genCmd = GEN_CSR_CMD

            subject = params['subject'].format(hname=params['hostname'])
            genCmd = genCmd.format(hname=params['hostname'], subject=subject)
            if args.verb:  err('\n-- CSR generation command:   {}'.format(genCmd))
            shell(genCmd)
            csrFile = params['hostname']+'.csr'

        with open(csrFile) as f:
            params['csr'] = f.read()

    if args.verb>1:
        err('\n==============   CSR   ==============')
        err(params['csr'])
        err(shell(SHOW_CSR_CMD.format(csrFile=csrFile)), end='')
        err('=====================================')

    if 'csr' not in passedArgs:
        err('\nCSR stored at ./{}'.format(csrFile))
        err('Key for requested cert stored at ./{}.key'.format(params['hostname']))

    if 'common_name' not in passedArgs:
        params['common_name'] = params['hostname']

    # Finally, remove 'subject' which was only used for CSR generation
    if 'subject' in params:  del params['subject']

    return params


def query(mykey, thequery, args, defaults):
    """
    Prepare the DigiCert API query/command and Request objects, send the request (unless
    dry run was requested) and return the reply from DigiCert.
    """

    # Select the type of query (and check/set specific actions/args)
    if   thequery == 'list':  

        q = qapi.ViewOrdersQuery(mykey)

        # Handle limit/offset options
        # First, check if they were used
        urlArgs = []
        if args.limit:   urlArgs.append('limit={0}'.format(args.limit))
        if args.offset:  urlArgs.append('offset={0}'.format(args.offset))

        if urlArgs:
            # This is a bit ugly... The API does not offer support for limit/offset, so we
            # need to manually (and after-the-fact) modify the URL function used for the query
            basepath = q.get_path()
            q.get_path = lambda: basepath + '?' + '&'.join(urlArgs)
        
    elif thequery == 'show':  q = qapi.ViewOrderDetailsQuery(mykey, order_id=args.id)
    elif thequery == 'me':    q = qapi.MyUserQuery(mykey)

    # Cert download is not simple, you need to first retrieve cert if (from order id), 
    # then perform the query
    elif thequery == 'download':  
        certId = query(mykey, 'show', args)['certificate']['id']
        if args.verb:  
            err('-- Got certificate ID: {} (for given order ID, {})'.format(certId, args.id))
        q = qapi.DownloadCertificateQuery(mykey, certificate_id=certId)

    # Cert request/renewal needs a preparation of body parameters
    elif thequery in ('reqcert', 'renew'):
        params = prepareParams(args, defaults, renew=(thequery=='renew'))
        q = capi.OrderCertificateCommand(mykey, **params)

        # Check --altNames option
        if params['sans']:
            # Next is hacky, API should put SANs info within 'certificate' by itself... but it doesn't
            q.certificate['dns_names'] = params['sans']

        # This is also hacky but basically just cosmetics
        del q.csr

    else:
        raise Exception('Not supported query {}'.format(thequery))
    
    # Build request with selected query/command
    req = dgc.Request(action=q, host=DGC_HOST)

    # Unless we're requesting/renewing a cert, empty the query's __dict__
    if thequery not in ('reqcert', 'renew'):
        # This shouldn't be needed, but it seems that if we don't do it, the request
        # doesn't work (probably it tries a POST instead of a GET)
        def ftemp():  return {}
        q.get_params = ftemp

    # Show what we'll submit
    if args.verb>1:
        toshow = q.__dict__.copy()
        toshow.pop('_customer_api_key')
        err('\n========= PREPARED REQUEST ==========')
        err('Host+path: {} {}'.format(req.host, q.get_path()))
        err('Headers:\n   ', end='')
        headers = q.get_headers().copy()
        headers.pop('X-DC-DEVKEY')
        pprint(headers, stream=sys.stderr)
        err('Params:\n   ', end='')
        pprint(toshow, stream=sys.stderr)
        err('=====================================\n')

    # Submit
    if not args.dry:

        if args.verb:  err("\n-- Sending '{}' request to DigiCert".format(thequery))
        res = req.send()

        return res


####   MAIN   ####
def main():
    """
     Performes the main task of the script (invoked directly).
     For information on its functionality, please call the help function.
    """
    
    # Options
    helpstr = """
Command line interface to query DigiCert (internally, this script uses DigiCert's python
API digiert_client, which in turn uses DigiCert's REST interface). Refs:

  REST API doc:  https://www.digicert.com/services/v2/documentation
  Python client: https://pypi.org/project/digicert_client


 **************************************************************************
 ***                        IMPORTANT NOTES                             ***
 ***                                                                    *** 
 ***   DigiCert API does not support Python 3. Please, use Python 2.    ***
 ***                                                                    ***
 ***   You may need to apply Pull #2 to digicert_client after install   ***
 ***     (https://github.com/digicert/digicert_client/pull/2)           ***
 ***                                                                    *** 
 **************************************************************************


Basics:

  You can perform a single type of query by selecting only one of the main options:

     --me / --list / --show / --down / --new / --renew 

  For every query, you need to specify your DigiCert API key for authentication, either
  by using -k option or by specifying it interactively.

  Some queries (--me/--list) need no additional information, while others
  (--show/--down/--renew) require that an order ID is specified as well (with --id).


Certificate request:

  A new cert can be requested (--new) or one renewed (--renew). For the moment, only host
  certificates are supported.  
  
  For certificate request, some input information is required. This information is either
  passed with a configuration file (--conf), or defaults may be used. The only parameter
  that is always required is the hostname (may be set directly with --hname).

  The defaults are obtained from a file called '{0}'. (may be overriden 
  with '--defaults' option). The file must contain a json-formatted dictionary of
  parameters (any parameter starting with '__' will be ignored). Please use --params for
  parameters typically used in the defaults file.

  The only always-required parameter (no default is accepted) is the hostname for the
  cert. You may use the --hname option to provide it (or include in the config file with
  --conf). The config file may also override defaults, or specify other optional
  parameters. The format is the following:
   
     [params]
     <param1>: <value1>
     <param2>: <value2>
     ...
  
  The leading '[params]' is literal, the rest must be replaced by real param names.

  Note that the request requires a CSR file, which, if not provided explicitely ('--csr'),
  is generated using the defaults/config file parameters, and the system's default openssl
  values.

  Special considerations for Multi Domain certificate:

     If you want to order a GRID Host SSL Multi Domain cert, you probably want to use
     '--alt' option to provide a list of comma-separated names to be included in the SAN
     field (in addition to that specified as 'hostname'). 
     
     Behind the scenes, this creates a temporary openssl conf file, based on system's
     default ({1}), but with the addition of the alt names,
     to generate the CSR file. One may customize this by setting his own SSL config file
     ('--ssl-conf'), or directly providing its own CSR file ('--csr').
     
     An alternative to using the '--alt' option is to manually include parameters
     'certificate_type' and 'sans' in the file passed to '--conf' (in that case, you
     also need to use '--ssl-conf').
  
  To see the complete list of default/optional parameters, use option --params.


Examples:

  List existing orders (API key will be asked interactively):

      dgc-query.py --list

  List 50 (max) orders, skipping the first 100 

      dgc-query.py -k api.key --list --off 100 --lim 50

  Show details of request with order ID 345:

      dgc-query.py -k api.key --show --id 345

  Ask for a new certificate (returns associated order ID):

      dgc-query.py -k api.key --new --hname myhost.ciemat.es

  Ask for a new certificate with additional hostnames:

      dgc-query.py -k api.key --new --hname myalias.ciemat.es --alt myhost1.ciemat.es,myhost2.ciemat.es

  Download certificate with order ID 345:
    
      dgc-query.py -k api.key --down --id 345

  Ask for a new certificate with additional configuration:

      dgc-query.py -k api.key --renew --hname myhost.ciemat.es --conf myconf.file

  Renew certificate with order ID 345:

      dgc-query.py -k api.key --renew --hname myhost.ciemat.es --id 345

""".format(DEFAULTS_FILE, OPENSSL_CONF)

    # Create parser with general help information
    parser = ArgumentParser(description=helpstr, formatter_class=RawTextHelpFormatter)

    # Set the version
    parser.add_argument('--version', action='version', version='%(prog)s 2.0')

    helpstr = "Be verbose (show additional information). Use twice for extra verbose."
    parser.add_argument( "-v", "--verbose", dest="verb", help=helpstr, action="count")

    helpstr = "Do not send request, generate request object and show it."
    parser.add_argument("--dry", dest="dry", help=helpstr, action="store_true")


    # Option usage 
    class UsageAction(Action):
        def __init__(self, option_strings, dest, nargs=None, **kwargs):
            Action.__init__(self, option_strings, dest, nargs=0, **kwargs)
        def __call__(self, parser, namespace, values, option_string=None):
            parser.print_usage()
            sys.exit(0)
    helpstr = "Show usage information"
    parser.add_argument("-u", "--usage", help=helpstr, action=UsageAction)
    def usage():
        parser.print_usage() 

    helpstr = "Get API key from file (otherwise it's asked interactively)."
    parser.add_argument("-k", "--key", dest="key", help=helpstr)
    
    # Mutually exclusive group: choose one query (not more!)
    group = parser.add_mutually_exclusive_group()
    #
    helpstr = "Show information about me"
    group.add_argument("-m", "--me", dest="me", help=helpstr, action="store_true")
    #
    helpstr = "List certificate orders"
    group.add_argument("-l", "--list", dest="list", help=helpstr, action="store_true")
    #
    helpstr = "Show details about specified (id) order (usually, a cert request). Requires --id."
    group.add_argument("-s", "--show", dest="show", help=helpstr, action="store_true")
    #
    helpstr = "Download specified (order id) certificate. Requires --id."
    group.add_argument("-d", "--download", dest="down", help=helpstr, action="store_true")
    #
    helpstr = "Request a new certificate. Requires --conf and/or --hname."
    group.add_argument("-n", "--new", dest="req", help=helpstr, action="store_true")
    #
    helpstr = "Renew an existing certificate. Requires --id."
    group.add_argument("-r", "--renew", dest="renew", help=helpstr, action="store_true")
    
    helpstr = "Show default/opt params for cert request conf file (no DigiCert query is sent)."
    parser.add_argument("--params", dest="params", help=helpstr, action="store_true")

    helpstr = "For -s/-d: specify order ID for request to query/cert to download."
    parser.add_argument("--id", dest="id", help=helpstr)
    
    helpstr = "For cert request: set defaults file (default: {})".format(DEFAULTS_FILE)
    parser.add_argument("--defaults", dest="defaults", default=DEFAULTS_FILE, help=helpstr)

    helpstr = "For cert request: set config file"
    parser.add_argument("--conf", dest="conf", help=helpstr)

    helpstr = "For cert request: set param 'hostname' (overrides conf file)."
    parser.add_argument("--hname", dest="hname", help=helpstr)
    
    helpstr = "For cert request: get CSR from file 'csr' (otherwise generate from conf values)."
    parser.add_argument("-c", "--csr", dest="csr", help=helpstr)

    helpstr = "For cert request: set additional hostnames (comma-separated) to be secured (SAN list)."
    parser.add_argument("--alt", dest="altNames", help=helpstr)
    
    helpstr = "For cert request: use specified openssl conf file."
    parser.add_argument("--ssl-conf", dest="sslConf", help=helpstr)
    
    helpstr = "For order list: set responses limit (default: 1000)."
    parser.add_argument("--limit", dest="limit", help=helpstr)

    helpstr = "For order list: set skip offset (of own orders)."
    parser.add_argument("--offset", dest="offset", help=helpstr)

    
    # Do parse options
    args = parser.parse_args()

    if not (args.me or args.list or args.down or args.show or args.req 
            or args.renew or args.params):
        err('ERROR: you need to use one of -m/-l/-d/-s/-n/-r/--params.')
        return 10

    if args.me:    thequery = 'me'
    if args.list:  thequery = 'list'
    if args.show:  thequery = 'show'
    if args.down:  thequery = 'download'
    if args.req:   thequery = 'reqcert'
    if args.renew: thequery = 'renew'

    try:
        with open(args.defaults) as f:
            defaults = json.load(f)
            todel = []
            for attr in defaults:
                if attr.startswith('__'): 
                    todel.append(attr)
            for attr in todel:  del(defaults[attr])
    except Exception as ex:
        err("ERROR: can't parse defaults file {0}:\n{1} ".format(args.defaults, ex))
        return 11

    if (args.down or args.show or args.renew) and (not args.id):
        err('ERROR: An order id must be specified for download/show/renew actions.')
        return 12

    if args.req and (not args.hname) and (not args.conf):
        err('ERROR: for cert request, you need to use --hname or --conf.')
        return 13

    if args.params:
        print('\nDefault params:')
        for param in defaultAttrs:  print('   -', param)
        print('\nAdditional optional params:')
        for param in moreParams:  print('   -', param)
        print()
        return 0

    if args.dry and (not args.verb):
        args.verb = 1

    # Shortcut for verbose
    verb = args.verb
    
    
    #### REAL MAIN ####
    
    # Read or ask for API key
    if args.key:
        with open(args.key) as f:
            mykey = f.read().strip()
    else:
        mykey = getpass("Please introduce your DigiCert API key: ").strip()
    

    res = query(mykey, thequery, args, defaults)

    if not args.dry:

        if args.verb:  err('\n-- Received response from DigiCert:\n')

        if args.down:  
            if args.verb:    
                if args.verb > 1:  printj(res, stream=sys.stderr)
                else:              err('--  Series of certs received (used -vv to show)')
                err('\n--  Host cert follows\n')
            print(res['certificates']['certificate'])

        elif args.req: 
            if args.verb:  
                printj(res, stream=sys.stderr)
                err('\n')
            print(res['id'])

        else:
            printj(res)

        
    # Exit successfully
    return 0


###    SCRIPT    ####
if __name__=="__main__":
    sys.exit(main())
