#!/usr/bin/env python

import sys, os, getopt, re, spur, logging#, coloredlogs
from socket import *

global F5_ARGS
global ACTION_LIST
global PORT_RANGE
F5_ARGS = {}
ACTION_LIST = ['disable','down','enable','show','up','conn','test', 'state']
PORT_RANGE = range(1,65537)
F5_ARGS['quiet'] = False
F5_ARGS['verbose'] = False
F5_ARGS['info'] = False
F5_ARGS['lbdefaultuser'] = 'lb_connector'
F5_ARGS['lb_password'] = "ubuntu-password"

def lb_executor(commands):
    logging.getLogger("paramiko").setLevel(logging.ERROR)
    shell = spur.SshShell(hostname=F5_ARGS['lbip'], username=F5_ARGS['user'], password=F5_ARGS['lb_password'], missing_host_key=spur.ssh.MissingHostKey.accept)
    with shell:
        result = shell.run(commands.split(' '))
        
def wi_conn_count(pool_command):
    print 'called node connection count function'
    
def wi_disable(pool_command):
    print pool_command + ' session disable"'
    
def wi_down(pool_command):
    print pool_command + ' down"'
    return True
    
def wi_enable(pool_command):
    print pool_command + ' session enable"'
    
def wi_up(pool_command):
    print pool_command + ' up"'
    
def wi_show(pool_command):
    print pool_command + ' show"'
        
def wi_state(pool_command):
    print pool_command + ' show" | awk ' + "'" +  '/^POOL/ {print $NF}' + "'"

def wi_test(pool_command):
    print pool_command + ' show" | awk ' + "'" +  '/^POOL/ {print $NF}' + "'"

def wo_conn_count(partition_command, instance):
    print partition_command

def wo_disable(partition_command, instance):
    ltm_command = partition_command + ' session user-disabled'
    lb_executor(ltm_command)

def wo_down(partition_command, instance):
    ltm_command = partition_command + ' state user-down'
    lb_executor(ltm_command)

def wo_enable(partition_command, instance):
    ltm_command = partition_command + ' session user-enabled'
    lb_executor(ltm_command)

def wo_up(partition_command, instance):
    ltm_command = partition_command + ' state user-up'
    lb_executor(ltm_command)

def wo_show(partition_command, instance):
    ltm_command = "list /ltm node /" + F5_ARGS['ptn'] + '/' + gethostbyname(instance)
    lb_executor(ltm_command)

def wo_state(partition_command, instance):
    ltm_command = "list /ltm node /" + F5_ARGS['ptn'] + '/' + gethostbyname(instance) + ' | grep session | awk \'{print $2}\'' 
    lb_executor(ltm_command)

def wo_test(partition_command, instance):
    ltm_command = partition_command
    lb_executor(ltm_command)

ACTIONS_WIPOOL = {"conn":wi_conn_count, "disable":wi_disable, "down":wi_down, "enable":wi_enable, "up":wi_up, "show":wi_show, "state":wi_state, "test":wi_test}
ACTIONS_WOPOOL = {"conn":wo_conn_count, "disable":wo_disable, "down":wo_down, "enable":wo_enable, "up":wo_up, "show":wo_show, "state":wo_state, "test":wo_test}

def multi(dispatch_fn):
    def _inner(*args, **kwargs):
        return _inner.__multi__.get(
            dispatch_fn(*args, **kwargs),
            _inner.__multi_default__
        )(*args, **kwargs)

    _inner.__multi__ = {}
    _inner.__multi_default__ = lambda *args, **kwargs: None  # Default default
    return _inner

def method(dispatch_fn, dispatch_key=None):
    def apply_decorator(fn):
        if dispatch_key is None:
            # Default case
            dispatch_fn.__multi_default__ = fn
        else:

            dispatch_fn.__multi__[dispatch_key] = fn
        return dispatch_fn
    return apply_decorator

@multi
def ACTIONS_F5(envon):
    return envon.get('type')

@method(ACTIONS_F5, 'not_set')
def ACTIONS_F5(not_set):
    #return 'NON POOL BASED: ' + not_set['command']
    return ACTIONS_WOPOOL[F5_ARGS['action']](not_set['wo_pool'], not_set['target_host'])

@method(ACTIONS_F5, 'name_set')
def ACTIONS_F5(name_set):
    #return 'POOL BASED: ' + name_set['command']
    return ACTIONS_WIPOOL[F5_ARGS['action']](name_set['wi_pool'])

@method(ACTIONS_F5)
def ACTIONS_F5(unknown_entry):
    raise Exception("Cannot identify the state!")
        
def validate_hostname(instance_x):
    """Example hostname pattern is sf1-ebates12.ebates.int"""
    hostname_pattern = re.compile('^[a-zA-Z]+\d+-[a-zA-Z]+\d+\.[a-zA-Z]+\.[a-zA-Z]+$', re.IGNORECASE)
    if hostname_pattern.match(instance_x) is not None:
        return True
    else:
        return False
    
def name2ip(host_name):
    try:
        gethostbyname(host_name)
    except:
        return False
    else:
        return True
        
def show_usage_and_exit(str, **exit_status_code):
    logging.error('Terminating F5 Operations, due to: %s', str)
    #usage()
    sys.exit(exit_status_code.get("code", 3))
    
def show_info():
    if F5_ARGS['quiet'] != True:
        print ' Load Balancer IP Address: ', F5_ARGS.get('lbip', "NIL")
        print '   Load Balancer username: ', F5_ARGS.get('user', "NIL")
        print '    LB configuration file: ', F5_ARGS.get('config', "NIL")
        print '    LB target node action: ', F5_ARGS.get('action', "NIL")
        print '      LB target node port: ', F5_ARGS.get('port', "NIL")
        print '          LB Pool name is: ', F5_ARGS.get('pool', "NIL")
        print '          LB target nodes: ', F5_ARGS.get('node', "NIL")
        print '                  Verbose: ', F5_ARGS.get('verbose', "NIL")
        print '                    Quiet: ', F5_ARGS.get('quiet', "NIL")

def usage():
    print os.path.basename(__file__),' -a <disable|down|enable|show|up|conn|test> -o <POOL> -p <PORT>'
    print '        -n <node1[,node2,nodeX]> [-vh] [-l <IP Address>] [-u <username>]'
    print ''
    print 'Changes load balancer configuration for specified nodes.'
    print ' -a|--action <action>  Action to perform. Supported actions are:'
    print '                       disable, down, enable, show, up, conn, test'
    print ' -h|--help             Show this help message'
    print ' -l|--lb-ip <IP>       Load balancer IP to control (default: $LB_VIRTUAL)'
    print ' -o|--pool <pool>      Take action against this pool. (Required)'
    print ' -p|--port <port>      Enable/disable this port, rather than a whole host'
    print ' -n|--node <node>      List of nodes (servers) to add, comma-separated'
    print '                       Example: node1,node2,node3 (no spaces)'
    print ' -u|--user <username>  Load balancer userid (default: $LB_USER_DEFAULT)'
    print ' -v|--verbose          Turn on Verbosity.  May break higher level scripts.'
    print ''
    print 'Example: ',os.path.basename(__file__),' -a disable -o common -n qa1-ebates1.ebates.int'


def main(argv):
    try:
        opts, args = getopt.getopt(argv,"ha:l:o:p:n:u:vc:qt:",["help", "action=", "lb-ip=", "pool=", "port=", "node=", "user=", "verbose", "config=", "quiet", "partition="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    except:
        raise

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-a", "--action"):
            F5_ARGS['action'] = arg
        elif opt in ("-l", "--lb-ip"):
            F5_ARGS['lbip'] = arg
        elif opt in ("-o", "--pool"):
            F5_ARGS['pool'] = arg
        elif opt in ("-n", "--node"):
            F5_ARGS['node'] = arg
        elif opt in ("-u", "--user"):
            F5_ARGS['user'] = arg
        elif opt in ("-p", "--port"):
            F5_ARGS['port'] = arg
        elif opt in ("-v", "--verbose"):
            F5_ARGS['loglvl'] = 'DEBUG'
        elif opt in ("-c", "--config"):
            F5_ARGS['config'] = arg
        elif opt in ("-q", "--quiet"):
            F5_ARGS['loglvl'] = 'CRITICAL'
        elif opt in ("-t", "--partition"):
            F5_ARGS['partition'] = arg
        #elif opt in ("-i", "--info"):
        #    F5_ARGS['info'] = True

    #if F5_ARGS.get('info', "False") == True:
    #    show_info()
    #enable_logging()
    
    FORMAT = '%(asctime)-15s %(name)-12s %(levelname)-8s ==> %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        format=FORMAT,
                        filename='/tmp/f5.log',
                        filemode='w')
    console = logging.StreamHandler()
    if os.isatty(sys.stdout.fileno()) == True:
        console.setLevel(logging.DEBUG)
    elif F5_ARGS.get('loglvl', "NOTSET") == "CRITICAL":
        console.setLevel(logging.CRITICAL)
    elif F5_ARGS.get('loglvl', "NOTSET") == "DEBUG":
        console.setLevel(logging.DEBUG)
    else:
        console.setLevel(logging.INFO)

    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s ==> %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    #coloredlogs.install(level='DEBUG')

    argument_logger = logging.getLogger('F5: Args')
#    node_logger = logging.getLogger('F5: Node')
    action_logger = logging.getLogger('F5: Actions')
    pool_logger = logging.getLogger('F5: Pool')

    logging.info('Starting F5 Operations.')
    argument_logger.debug("*******************************************************************")
    argument_logger.debug("Performing checks on supplied arguments and parameters.")
    
    if F5_ARGS.get('node', "empty") == "empty":
        argument_logger.warning('No target nodes specified.')
        show_usage_and_exit('No target nodes specified.', code=3)
    else:
        for node_name_validate in F5_ARGS.get('node').split(","):
            if validate_hostname(node_name_validate):
                if name2ip(node_name_validate):
                    pass
                else:
                    argument_logger.warning("DNS name not resolved for node : %s", node_name_validate)
                    show_usage_and_exit('DNS not able to resolve provided node name.', code=101)
            else:
                argument_logger.warning("Invalid node name format: %s", node_name_validate)
                show_usage_and_exit('Invalid node name format.', code=100)
            
        argument_logger.debug("Node list: %s", [node for node in F5_ARGS.get('node').split(",")])
    
    if F5_ARGS.get('action', "empty") == "empty":
        argument_logger.warning('Target action not specified.')
        show_usage_and_exit('Target action not specified.', code=4)
    elif F5_ARGS['action'] not in ACTION_LIST:
        argument_logger.warning('Invalid target action specified: %s', F5_ARGS['action'])
        argument_logger.warning('Valid target actions are: %s', ACTION_LIST)
        show_usage_and_exit('Invalid target action.', code=5)
    else:
        argument_logger.debug("Action to be performed: %s", F5_ARGS['action'].upper()) 
        
    if (F5_ARGS.get('port', "empty") != "empty"):
        try:
            int(F5_ARGS.get('port', 0))
        except ValueError as error:
            argument_logger.warning('Invalid system port number: %s', F5_ARGS['port'])
            show_usage_and_exit('Port number is not numeric.', code=6)
        except:
            argument_logger.warning('Port number is not an integer: %s', F5_ARGS['port'])
            show_usage_and_exit('Unknown issue with port number.', code=7)
#        else:
#            argument_logger.debug('Port number provided is convertible to integer.')

        if (int(F5_ARGS['port']) not in PORT_RANGE):
            argument_logger.warning('Invalid port number specified: %d', int(F5_ARGS['port']))
            argument_logger.warning('Valid port numbers are between 0-65538.')
            show_usage_and_exit('Invalid port number specified.', code=8)
        else: #(F5_ARGS.get('port', "empty") != "empty"):
            argument_logger.debug("Port number is: %s", F5_ARGS['port']) 
            F5_ARGS['port'] = ':' + F5_ARGS['port']
    else:
        if F5_ARGS['action'] != "test":
            argument_logger.warning('Port number not specified.')
            argument_logger.warning('This will take action against the entire node.')
            argument_logger.warning('If this was unintentional, please use the -p option.')
    
    if F5_ARGS.get('lbip', "empty") == "empty":
        argument_logger.warning('Load balancer is not specified.')
        argument_logger.warning('Please use the -l option.')
        show_usage_and_exit('Load Balancer ip/hostname missing.', code=9)
    
    if F5_ARGS.get('lbip', "empty") != "empty":
        s = socket(AF_INET, SOCK_STREAM, 0)
        s.settimeout(0.5)
        try:
            s.connect((F5_ARGS['lbip'], 80))
            s.close()
        except timeout as error:
            argument_logger.warning('Timed out, trying to reach the LB.')
            show_usage_and_exit('Load Balancer connection timming out.', code=10)
        except gaierror as error:
            argument_logger.warning('LB Hostname does not resolve.')
            show_usage_and_exit('Load Balancer hostname does not resovle.', code=11)
        except:
            argument_logger.warning('Not able to connect to Load Balancer.')
            show_usage_and_exit('Not able to connect to LB.', code=12)
        else:
            argument_logger.debug('Network connection was successful to LB: %s', F5_ARGS['lbip'])
    
    if F5_ARGS.get('user', "empty") == "empty":
        F5_ARGS['user'] = F5_ARGS['lbdefaultuser']
        argument_logger.warning('No username was specified for load balancer: %s', F5_ARGS['lbip'])
        argument_logger.warning('Hence setting default username for LB access: %s', F5_ARGS['user'].upper())
    else:
        argument_logger.debug('Username specified for load balancer: %s', F5_ARGS['user'].upper())
        
    if F5_ARGS.get('pool', "empty") == "empty":
        F5_ARGS['pool'] = "not_set"
        F5_ARGS['pool_state'] = "not_set"
        argument_logger.warning('No pool name was specified, hence not using pool')
        argument_logger.warning('If this was unintentional, please use the -o option.')
    else:
        F5_ARGS['pool_state'] = "name_set"
        argument_logger.debug('Using provided LB Pool name: %s', F5_ARGS['pool'])
        
    if F5_ARGS.get('partition', "empty") == "empty":
        F5_ARGS['ptn'] = "default_partition"
        argument_logger.warning('No parition name has been specified, hence using default partition')
    else:
        F5_ARGS['ptn'] = F5_ARGS['partition']
    
    argument_logger.debug("Checks on supplied arguments and parameters completed successfully.")
    argument_logger.debug("*******************************************************************")
    
    for node_instance in [node for node in F5_ARGS.get('node').split(",")]:
        action_logger.debug('Initiating action %s on node %s', F5_ARGS['action'].upper(), node_instance.upper())
        #pool_command = 'ssh ' + F5_ARGS['user'] + '@' + F5_ARGS['lbip'] + ' "pool ' + F5_ARGS['pool'] + ' member ' + gethostbyname(node_instance) + F5_ARGS.get('port', "")
        pool_command = '"pool ' + F5_ARGS['pool'] + ' member ' + gethostbyname(node_instance) + F5_ARGS.get('port', "")
        #partition_command = 'ssh ' + F5_ARGS['user'] + '@' + F5_ARGS['lbip'] + ' "modify ltm node /' + F5_ARGS['ptn'] + '/'+ gethostbyname(node_instance) 
        partition_command = 'modify ltm node /' + F5_ARGS['ptn'] + '/'+ gethostbyname(node_instance) 
        ACTIONS_F5({'type': F5_ARGS['pool_state'], 'wi_pool': pool_command, 'wo_pool': partition_command, 'target_host': node_instance})
        action_logger.debug('Finished action %s on node %s', F5_ARGS['action'].upper(), node_instance.upper())
        action_logger.debug("*******************************************************************")

if __name__ == "__main__":
	if len(sys.argv) == 1:
		usage()
		sys.exit(1)
	main(sys.argv[1:])