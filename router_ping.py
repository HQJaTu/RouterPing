#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import sys
import argparse
from multiping import MultiPing
import logging
from apscheduler.schedulers.blocking import BlockingScheduler
from daemonize import Daemonize
import signal
import os
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from subprocess import Popen, PIPE
from datetime import date, timedelta

DEFAULT_INTERVAL = 10
DEFAULT_PID_FILE = '/var/run/router_ping.pid'


class RollingLogger(logging.handlers.TimedRotatingFileHandler):
    """
    Inherited TimedRotatingFileHandler.
    """

    def __init__(self, filename, mail_cb, mail_cb_args):
        """
        Create the actual logger for this inherited class /w suitable defaults.
        :param filename:
        :return:
        """
        super(RollingLogger, self).__init__(filename,
                                            encoding='utf-8', utc=False, when='midnight')

        # Store the newly out-rotated filename
        self.previous_filename = None

        # Do send a mail callback
        self.mail_cb = mail_cb
        self.mail_cb_args = mail_cb_args

    def rotate(self, source, dest):
        super(RollingLogger, self).rotate(source, dest)

        # Store the newly out-rotated filename
        self.previous_filename = dest

    def doRollover(self):
        self.previous_filename = None

        # Do the actual roll-over
        super(RollingLogger, self).doRollover()

        # Sanity:
        # Make sure we have the out-rotated filename.
        if not self.previous_filename:
            return

        # Send the previous log in an email
        if self.mail_cb_args:
            self.mail_cb(self.previous_filename, self.mail_cb_args)


def ping(host, n=1, timeout=1, retry_on_failure=True):
    """
    Ping a host
    :param host: host to ping
    :type host: str
    :param n: ping how many times, default=1
    :type n: int
    :param timeout: Timeout in seconds. How long to wait for ICMP response.
    :type timeout: int
    :param retry_on_failure: Do a final attempt on those hosts, which failed to respond.
    :type retry_on_failure: bool
    :return: float Round Trip Time [s]
    """
    if n < 1:
        raise ValueError("n needs to be a positive integer")
    if n > 1:
        avg = 0
        for i in range(n):
            avg += ping(host)
        avg = avg / n

        return avg

    # Pinging only once.
    # Create a MultiPing object to test hosts / addresses
    mp = MultiPing([host])

    # Send the pings to those addresses
    mp.send()

    # With a 1 second timeout, wait for responses (may return sooner if all
    # results are received).
    responses, no_responses = mp.receive(timeout)

    rtt = None
    for addr, rtt in responses.items():
        rtt = rtt

    if retry_on_failure and no_responses:
        # Sending pings once more, but just to those addresses that have not
        # responded, yet.
        mp.send()
        responses, no_responses = mp.receive(timeout)

    return rtt


def pinger(logger, host):
    """
    Do one round of pinging and logging.
    Triggered by scheduler.
    :param logger:
    :param host: host to ping
    :type host: str
    :return:
    """
    rtt = ping(host, retry_on_failure=False)
    if rtt is not None:
        logger.info("%s is up, RTT %f" % (host, rtt))
    else:
        logger.error("%s is down" % host)
    # super(logging.FileHandler, fh).flush()


def log_pings(host, filename, interval, mail_to):
    """
    Main loop
    :param host: host to ping
    :type host: str
    :param filename: Filename to log to
    :type filename: str
    :param interval: Interval of ping runs [s]
    :type interval: int
    :return:
    """
    mail_args = {}
    if mail_to:
        mail_args['mail_to'] = mail_to

    logger = logging.getLogger(__name__)
    log_handler = RollingLogger(filename, send_mail_about_log, mail_args)
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    log_handler.setFormatter(log_formatter)
    logger.addHandler(log_handler)
    logger.setLevel(logging.DEBUG)

    logger.info("Start pinging %s" % host)

    scheduler = BlockingScheduler()
    scheduler.add_job(pinger, args=[logger, host],
                      trigger='interval', seconds=interval)
    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    try:
        scheduler.start()
    except KeyboardInterrupt:
        exit_gracefully(None, None)


def exit_gracefully(signum, frame):
    """
    Signal handler.
    Stop main loop and quit.
    :param signum:
    :param frame:
    :return:
    """
    logger = logging.getLogger(__name__)
    # logger.debug("exit_gracefully() called!")

    logger.info("Stop pinging")
    exit(0)


def send_mail_about_log(filename, args):
    yesterday_was = date.today() - timedelta(days=1)
    yesterday_day = yesterday_was.strftime('%Y-%m-%d')
    email = MIMEMultipart()
    email['Subject'] = 'Router ping logs for %s' % yesterday_day
    email['To'] = args['mail_to']

    part = MIMEBase('application', "octet-stream")
    part.set_payload(open(filename, "rb").read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment; filename="%s.log"' % os.path.basename(filename))
    email.attach(part)

    p = Popen(["/usr/sbin/sendmail", "-t", "-oi"], stdin=PIPE, universal_newlines=True)
    p.communicate(email.as_string())


def main():
    parser = argparse.ArgumentParser(description='Router pinger')
    parser.add_argument('host',
                        help='Host to ping')
    parser.add_argument('-i', '--interval',
                        default=DEFAULT_INTERVAL,
                        help='Interval of pinging')
    parser.add_argument('-f', '--log-file', dest='logfile',
                        help='Log file to log into')
    parser.add_argument('-d', '--daemon', action="store_true",
                        help='Fork into background as a daemon')
    parser.add_argument('-p', '--pid-file', dest='pidfile',
                        default=DEFAULT_PID_FILE,
                        help='Pidfile of the process')
    parser.add_argument('-t', '--mail-to', dest='mailto',
                        help='On midnight rotation, send the old log to this email address.')

    args = parser.parse_args()

    if args.host:
        rtt = ping(args.host)
        if rtt is not None:
            print("Test ping %s is up, RTT %f" % (args.host, rtt))
        else:
            print("Test ping %s is down" % (args.host,))
    else:
        parser.print_help(sys.stderr)
        exit(1)
    if not args.logfile:
        parser.print_help(sys.stderr)
        exit(1)

    # Sanity check interval
    args.interval = int(args.interval)
    if args.interval <= 0:
        parser.print_help(sys.stderr)
        exit(1)

    if args.daemon:
        # Go daemon!
        daemon = Daemonize(app="router_ping.py", pid=args.pidfile,
                           action=lambda: log_pings(args.host, args.logfile, args.interval, args.mailto),
                           foreground=False)
        daemon.start()
        # Never reached

    # Go foreground.
    log_pings(args.host, args.logfile, args.interval, args.mailto)
    # Never reached


if __name__ == "__main__":
    main()
