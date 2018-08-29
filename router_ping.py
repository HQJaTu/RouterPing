#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import sys
import argparse
from multiping import MultiPing
import logging
from apscheduler.schedulers.blocking import BlockingScheduler
from daemonize import Daemonize
import signal

DEFAULT_INTERVAL = 10
DEFAULT_PID_FILE = '/var/run/router_ping.pid'


def ping(host, n=0, timeout=1, retry_on_failure=True):
    if (n > 0):
        avg = 0
        for i in range(n):
            avg += ping(host)
        avg = avg / n

    # Create a MultiPing object to test hosts / addresses
    mp = MultiPing([host])

    # Send the pings to those addresses
    mp.send()

    # With a 1 second timout, wait for responses (may return sooner if all
    # results are received).
    responses, no_responses = mp.receive(timeout)

    RTT = None
    for addr, rtt in responses.items():
        RTT = rtt

    if retry_on_failure and no_responses:
        # Sending pings once more, but just to those addresses that have not
        # responded, yet.
        mp.send()
        responses, no_responses = mp.receive(timeout)

    return RTT


def pinger(logger, host):
    rtt = ping(host, retry_on_failure=False)
    if rtt is not None:
        logger.info("%s is up, RTT %f" % (host, rtt))
    else:
        logger.error("%s is down" % host)
    # super(logging.FileHandler, fh).flush()


def log_pings(host, filename, interval):
    logger = logging.getLogger(__name__)
    log_handler = logging.handlers.TimedRotatingFileHandler(filename, encoding='utf-8',
                                                            when='midnight')
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
    logger = logging.getLogger(__name__)
    # logger.debug("exit_gracefully() called!")

    logger.info("Stop pinging")
    exit(0)


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
                           action=lambda: log_pings(args.host, args.logfile, args.interval),
                           foreground=False)
        daemon.start()
        # Never reached

    # Go foreground.
    log_pings(args.host, args.logfile, args.interval)
    # Never reached


if __name__ == "__main__":
    main()
