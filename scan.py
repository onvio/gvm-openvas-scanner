#!/usr/bin/python

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.protocols.gmpv9 import AliveTest
from gvm.protocols.gmpv9 import CredentialType
from gvm.transforms import EtreeTransform
import logging
import os, sys, time, random
import optparse
from lxml import etree
from pathlib import Path
import base64

usage = "usage: %prog [options] hosts reportname"
parser = optparse.OptionParser(usage)

parser.add_option('-n', '--no-ping',
    action="store_false", dest="consider_alive",
    help="Consider all hosts as alive", default=False)

parser.add_option('--ssh-username',
    action="store", dest="ssh_username",
    help="SSH Username", default=None)

parser.add_option('--ssh-password',
    action="store", dest="ssh_password",
    help="SSH Password", default=None)

parser.add_option('--ssh-private-key',
    action="store", dest="ssh_private_key",
    help="SSH Private Key", default=None)

parser.add_option('--ssh-key-phrase',
    action="store", dest="ssh_private_key_phrase",
    help="SSH Private Key Phrase", default=None)

parser.add_option('--ssh-port',
    action="store", dest="ssh_port",
    help="SSH Port", default=22)

parser.add_option('-s', '--scan-config',
    action="store", dest="scan_config",
    help="Scan Configuration, Base or Full and fast", default="Base")

parser.add_option('-l', '--loglevel',
    action="store", dest="loglevel",
    help="Set loglevel", default="INFO")

options, args = parser.parse_args()
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', datefmt='[%Y-%m-%d %H:%M:%S]', level=options.loglevel.upper())

if len(args) != 2:
    parser.print_help()
    sys.exit()

hosts = args[0]
outputfile = args[1]

logging.info('Hosts: {}'.format(hosts))
logging.info('Outputfile: {}'.format(outputfile))

connection = TLSConnection()
transform = EtreeTransform()

logging.info('Connecting to GMP')

with Gmp(connection, transform=transform) as gmp:
    gmp.authenticate('admin', 'admin')
    logging.info('Authenticated')

    # Get the base config based on the provided name
    base_config = gmp.get_configs(filter="name=\"{}\"".format(options.scan_config),details=True)
    config_exists = len(base_config.xpath("//config")) == 1
    if not config_exists:
        logging.error('Selected config "%s" does not exist' % options.scan_config)
        sys.exit()
    base_config_id = base_config.xpath("//config")[0].get("id")

    # Create a custom config and change some settings, because gmp.set_nvt_preference does not work.
    custom_config_name = "{} - CUSTOM".format(options.scan_config)
    custom_config = gmp.get_configs(filter="name=\"{}\"".format(custom_config_name), details=True)
    # always import a new config
    custom_config_exists = False #len(custom_config.xpath("//config")) == 1

    if not custom_config_exists:
        logging.info('Cloning from config: {}'.format(base_config_id))
        config_import = etree.tostring(base_config).decode('utf-8')
        logging.debug("config_import: {}".format(config_import))
        config_import = config_import.replace('<name>{}</name>'.format(options.scan_config), '<name>{}</name>'.format(custom_config_name))
        # Enable TCP-SYN ping to check alive hosts
        config_import = config_import.replace('<name>Do a TCP ping</name><type>checkbox</type><value>no</value>', '<name>Do a TCP ping</name><type>checkbox</type><value>yes</value>')
        config_import = config_import.replace('<name>TCP ping tries also TCP-SYN ping</name><type>checkbox</type><value>no</value>', '<name>TCP ping tries also TCP-SYN ping</name><type>checkbox</type><value>yes</value>')
        logging.debug("modified config_import: {}".format(config_import))
        import_config = gmp.import_config(config=config_import)
        config_id = import_config[0].get("id")
    else:
        config_id = custom_config.xpath("//config")[0].get("id")

    logging.info('Starting scan with config: {}'.format(config_id))

    credential_id = None
    if options.ssh_username:
        if not options.ssh_password and not options.ssh_private_key:
            logging.error("SSH Username is provided, but no password or private key.")
            sys.exit()

        credential_name = "Credentials-{}".format(random.randint(1,99999))
        create_credential = gmp.create_credential(name=credential_name,
                                credential_type=CredentialType.USERNAME_PASSWORD,
                                allow_insecure=True,
                                login=options.ssh_username,
                                password=options.ssh_password,
                                private_key=options.ssh_private_key,
                                key_phrase=options.ssh_private_key_phrase)

        credential_id = create_credential.xpath("//create_credential_response")[0].get("id")
        logging.info("Created credential: {}".format(credential_id))

    # Bug in GVM, this does not work, patched but no released https://github.com/greenbone/ospd-openvas/pull/334
    alive_tests = AliveTest.ICMP_AND_TCP_ACK_SERVICE_PING
    if options.consider_alive:
        alive_tests = AliveTest.CONSIDER_ALIVE
    port_list_id = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5" # All IANA assigned TCP
    scan_name = "scan-{}".format(random.randint(1,99999))
    host_list = hosts.split(",")

    create_target = gmp.create_target(name = scan_name,
                                        hosts = host_list, 
                                        alive_test = alive_tests, 
                                        port_list_id=port_list_id, 
                                        ssh_credential_port=options.ssh_port,
                                        ssh_credential_id=credential_id)
    target_id = create_target.xpath("//create_target_response")[0].get("id")
    logging.info("Created target: {}".format(target_id))
    logging.info("Alive test: {}".format(alive_tests))
    logging.info("Port list: {}".format(port_list_id))
    logging.info("Scan name: {}".format(scan_name))
    logging.info("Host list: {}".format(host_list))

    default_scanner_id = "08b69003-5fc2-4037-a479-93b440211c73" # OpenVAS Default Scanner
    create_task = gmp.create_task(name = scan_name, 
                                    scanner_id = default_scanner_id, 
                                    config_id = config_id, 
                                    target_id = target_id)
    task_id = create_task.xpath("//create_task_response")[0].get("id")
    logging.info("Created task: {}".format(task_id))

    start_task = gmp.start_task(task_id = task_id)
    report_id = start_task.xpath("/start_task_response/report_id")[0].text
    logging.info("Started task with report: {}".format(report_id))

    progress = 0
    while progress != -1:
        get_task = gmp.get_task(task_id = task_id)
        status = get_task.xpath("//status")[0].text
        progress = int(get_task.xpath("//progress")[0].text)
        logging.info("Progress: {} {}%".format(status, progress))
        time.sleep(10)

    try:
        openvaslog = open("/usr/local/var/log/gvm/openvas.log", "r").read()
        logging.debug("openvas.log: {}".format(openvaslog))
    except FileNotFoundError as ex:
        logging.error(ex)
        
    report_formats = [("pdf", "c402cc3e-b531-11e1-9163-406186ea4fc5"), ("xml", "a994b278-1f62-11e1-96ac-406186ea4fc5")]

    for report_format, report_format_id in report_formats:
        logging.info("Building report: {}".format(report_format))

        report_filename = os.path.split(outputfile)[1]
        export_path = "/var/reports/{}.{}".format(report_filename, report_format)
        get_report = gmp.get_report(report_id = report_id, 
                                    report_format_id=report_format_id, 
                                    details=True, 
                                    ignore_pagination=True)

        try:
            if report_format == "pdf":
                report_content = get_report.xpath("//report[@id='{}']/text()".format(report_id))[0]
                binary_base64_encoded_pdf = report_content.encode('ascii')
                binary_pdf = base64.b64decode(binary_base64_encoded_pdf)
                pdf_path = Path(export_path).expanduser()
                pdf_path.write_bytes(binary_pdf)
            if report_format == "xml":
                report_content = get_report.xpath("(//report[@id='{}'])[2]".format(report_id))[0]
                report_content = etree.tostring(report_content).decode('utf-8')
                f = open(export_path, 'w')
                f.write(report_content)
                f.close()

            logging.info("Written {} report to: {}".format(report_format.upper(), export_path))
        except Exception as ex:
            logging.error(ex)

    # Cleanup
    gmp.delete_task(task_id = task_id, ultimate=True)
    gmp.delete_target(target_id = target_id, ultimate=True)
    gmp.delete_report(report_id = report_id)
    if credential_id:
        gmp.delete_credential(credential_id = credential_id, ultimate=True)

logging.info("Done!")
