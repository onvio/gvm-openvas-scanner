#!/usr/bin/python

import logging
import os, sys, time, random
import subprocess
import optparse
from lxml import etree
from pathlib import Path
import base64
from subprocess import CalledProcessError

parser = optparse.OptionParser()

parser.add_option('-n', '--no-ping',
    action="store_false", dest="consider_alive",
    help="Consider all hosts as alive", default=False)

parser.add_option('-u', '--username',
    action="store", dest="ssh_username",
    help="SSH Username", default="")

parser.add_option('-p', '--password',
    action="store", dest="ssh_password",
    help="SSH Password", default="")

parser.add_option('-k', '--key',
    action="store", dest="ssh_key",
    help="SSH Private Key", default="")

parser.add_option('-s', '--scan_config',
    action="store", dest="scan_config",
    help="Scan Configuration, Basic or Full", default="basic")

parser.add_option('-l', '--loglevel',
    action="store", dest="loglevel",
    help="Set loglevel", default="INFO")

options, args = parser.parse_args()

if len(sys.argv) < 3:
    logging.error('Usage: %s <scan targets> <output file>\r\nUse -h or --help to view options' % sys.argv[0])
    sys.exit()

hosts = args[0]
outputfile = args[1]

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d,%H:%M:%S', level=options.loglevel.upper())

def run_command(xml: str, xpath: str = ""):
    gvm_logon = "gvm-cli --gmp-username admin --gmp-password admin tls --hostname 127.0.0.1"
    command = "{} --xml '{}'".format(gvm_logon, xml)
    logging.debug("command: {}".format(command))
    command_result = ""
    try:
        command_response = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
        logging.debug("command_response: {}".format(command_response[:2000]))
        command_result = etree.XML(command_response)
        if xpath:
            command_result = command_result.xpath(xpath)
        logging.debug("command_result: {}".format(command_result[:2000]))
    except CalledProcessError as exc:
        logging.error(exc.output)
    return command_result

scan_configs = {
    "basic": "d21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663",
    "full": "daba56c8-73ec-11df-a475-002264764cea"
}

config_id = scan_configs[options.scan_config.lower()]

logging.info('Starting scan with config: {}'.format(config_id))

configs_response = run_command("<get_configs />", "//get_configs_response")[0]
logging.info("Available configs: {}".format(configs_response))

create_target_sshcredential = ""
if options.ssh_username:
    if options.ssh_password:
        creds_key = "<password>{}</password>".format(options.ssh_password)
    elif options.ssh_key:
        creds_key = "<key><private>{}</private></key>".format(options.ssh_key)
    else:
        logging.error("No SSH Password or Private Key provided.")
        sys.exit("No SSH Password or Private Key provided.")

    create_credential = "<create_credential><name>Credentials-{}</name><login>{}</login>{}</create_credential>".format(random.randint(1,99999), options.ssh_username, creds_key)
    credential_id = run_command(create_credential, "//create_credential_response")[0].get("id")
    logging.info("Created credential: {}".format(credential_id))
    create_target_sshcredential = "<ssh_credential id=\"{}\"><port>22</port></ssh_credential>".format(credential_id)

alive_tests = "<alive_tests>ICMP, TCP-ACK Service &amp; ARP Ping</alive_tests>"
if options.consider_alive:
    alive_tests = "<alive_tests>Consider Alive</alive_tests>"

# 33d0cd82-57c6-11e1-8ed1-406186ea4fc5 = All IANA assigned TCP

create_target = "<create_target><name>scan-{0}</name><hosts>{1}</hosts><port_list id=\"33d0cd82-57c6-11e1-8ed1-406186ea4fc5\" />{2}{3}</create_target>".format(random.randint(1,99999), hosts, alive_tests, create_target_sshcredential)
target_id = run_command(create_target, "//create_target_response")[0].get("id")
logging.info("Created target: {}".format(target_id))

create_task = "<create_task><name>Scan Suspect Host</name><target id=\"{}\"></target><config id=\"{}\"></config></create_task>".format(target_id, config_id)
task_id = run_command(create_task, "//create_task_response")[0].get("id")
logging.info("Created task: {}".format(task_id))

start_task = "<start_task task_id=\"{}\"/>".format(task_id)
report_id = run_command(start_task, "/start_task_response/report_id")[0].text
logging.info("Started task with report: {}".format(report_id))

status = ""
while status != ("Done" or "Stopped"):
    try:
        status_command = "<get_tasks task_id=\"{}\"/>".format(task_id)
        status_response = run_command(status_command)
        status = status_response.xpath("//status")[0].text
        progress = status_response.xpath("//progress")[0].text
        logging.info("Progress: {} {}%".format(status, progress))
        time.sleep(10)
    except subprocess.CalledProcessError as exc:
        logging.error(exc.output)

openvaslog = open("/usr/local/var/log/gvm/openvas.log", "r").read()
logging.debug("openvas.log: {}".format(openvaslog))
    
report_formats = [("pdf", "c402cc3e-b531-11e1-9163-406186ea4fc5"), ("xml", "a994b278-1f62-11e1-96ac-406186ea4fc5")]

for report_format, report_format_id in report_formats:
    logging.info("Building report: {}".format(report_format))

    report_filename = os.path.split(outputfile)[1]
    export_path = "/var/reports/{}.{}".format(report_filename, report_format)
    get_report_command = "<get_reports report_id=\"{}\" format_id=\"{}\" filter=\"first=1 rows=-1 apply_overrides=1 levels=hmlg sort-reverse=severity\" details=\"1\" />".format(report_id, report_format_id)

    try:
        if report_format == "pdf":
            report_content = run_command(get_report_command, "//report[@id='{}']/text()".format(report_id))[0]
            binary_base64_encoded_pdf = report_content.encode('ascii')
            binary_pdf = base64.b64decode(binary_base64_encoded_pdf)
            pdf_path = Path(export_path).expanduser()
            pdf_path.write_bytes(binary_pdf)
            logging.info("Written {} report to: {}".format(report_format.upper(), export_path))
        if report_format == "xml":
            report_content = run_command(get_report_command, "(//report[@id='{}'])[2]".format(report_id))[0]
            report_content = etree.tostring(report_content).decode('utf-8')
            f = open(export_path, 'w')
            f.write(report_content)
            f.close()
            logging.info("Written {} report to: {}".format(report_format.upper(), export_path))
    except Exception as e:
        logging.error(get_report_command)
        logging.error(e.output)

logging.info("Done!")
