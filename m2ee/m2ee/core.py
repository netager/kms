#
# Copyright (C) 2009 Mendix. All rights reserved.
#

import logging
import os
import codecs
import time
import copy
from typing import Optional

from m2ee.config import M2EEConfig
from m2ee.client import M2EEClient
from m2ee.runner import M2EERunner
from m2ee.version import MXVersion
from m2ee.exceptions import M2EEException

from m2ee import util

logger = logging.getLogger(__name__)


class M2EE():

    def __init__(self, yaml_files=None):
        self._yaml_files = yaml_files
        self.reload_config()
        self._logproc = None

    def reload_config_if_changed(self):
        if self.config.mtime_changed():
            logger.info("Configuration change detected, reloading.")
            self.reload_config()

    def reload_config(self):
        self.config = M2EEConfig(yaml_files=self._yaml_files)
        self.client = M2EEClient(
            'http://127.0.0.1:%s/' % self.config.get_admin_port(),
            self.config.get_admin_pass())
        self.runner = M2EERunner(self.config, self.client)

    def check_alive(self):
        pid_alive = self.runner.check_pid()
        m2ee_alive = self.client.ping()

        if pid_alive and not m2ee_alive:
            logger.error("The application process seems to be running "
                         "(pid %s is alive), but is not accessible for "
                         "administrative requests." % self.runner.get_pid())
            logger.error("If this is not caused by a configuration error "
                         "(e.g. wrong admin_port) setting, it could be caused "
                         "by JVM Heap Space / Out of memory errors. Please "
                         "review the application logfiles. In case of JVM "
                         "errors, you should consider restarting the "
                         "application process, because it is likely to be in "
                         "an undetermined broken state right now.")
        elif not pid_alive and m2ee_alive:
            logger.error("pid %s is not available, but m2ee responds" %
                         self.runner.get_pid())
        return (pid_alive, m2ee_alive)

    def start_appcontainer(self, detach=True, timeout=60):
        logger.debug("Checking if the runtime is already alive...")
        (pid_alive, m2ee_alive) = self.check_alive()
        if pid_alive is True or m2ee_alive is True:
            raise M2EEException("There's already a MxRuntime process running, aborting start. "
                                "If the application is not functional, or failed to start "
                                "earlier, try stop or restart first.",
                                errno=M2EEException.ERR_START_ALREADY_RUNNING)

        if not self.config.all_systems_are_go():  # TODO: Exception later
            raise M2EEException("Cannot start MxRuntime due to previous critical errors.",
                                errno=M2EEException.ERR_MISSING_CONFIG)

        version = self.config.get_runtime_version()

        if version // 5 or version // 6:
            self.config.write_felix_config()

        if self.config.get_symlink_mxclientsystem():
            util.fix_mxclientsystem_symlink(self.config)

        logger.info("Trying to start the MxRuntime...")
        self.runner.start(detach=detach, timeout=timeout)
        logger.debug("MxRuntime status: %s" % self.client.runtime_status()['status'])

        # go do startup sequence
        self._configure_logging()
        self._send_mime_types()

        if version < 5:
            self._send_jetty_config()
        else:
            self.client.update_appcontainer_configuration({
                "runtime_port": self.config.get_runtime_port(),
                "runtime_listen_addresses":
                self.config.get_runtime_listen_addresses(),
                "runtime_jetty_options": self.config.get_jetty_options()
            })

    def start_runtime(self, params=None, timeout=None):
        if params is None:
            params = {}
        logger.debug("MxRuntime status: %s" % self.client.runtime_status()['status'])
        self.client.start(params, timeout)
        logger.debug("MxRuntime status: %s" % self.client.runtime_status()['status'])
        logger.info("The MxRuntime is fully started now.")

    def stop(self, timeout=30):
        if self.client.ping():
            logger.info("Waiting for the application to shutdown...")
            stopped = self.runner.stop(timeout)
            if stopped:
                logger.info("The application has been stopped successfully.")
                return True
            else:
                logger.warning("The application did not shutdown by itself...")
                return False
        else:
            if self.runner.check_pid():
                logger.warning("Admin API not available, so not able to use shutdown action.")
                return False
            else:
                logger.info("Nothing to stop, the application process is not running.")
                self.runner.cleanup_pid()
                return True

    def terminate(self, timeout=10):
        if self.runner.check_pid():
            logger.info("Waiting for the JVM process to disappear...")
            stopped = self.runner.terminate(timeout)
            if stopped:
                logger.info("The JVM process has been stopped.")
                return True
            logger.warning("The application process seems not to respond to any "
                           "command or signal.")
            return False
        else:
            self.runner.cleanup_pid()
        return True

    def kill(self, timeout=10):
        if self.runner.check_pid():
            logger.info("Waiting for the JVM process to disappear...")
            stopped = self.runner.kill(timeout)
            if stopped:
                logger.info("The JVM process has been destroyed.")
                return True
            logger.error("Stopping the application process failed thorougly.")
            return False
        else:
            self.runner.cleanup_pid()
        return True

    def _configure_logging(self):
        logger.debug("Setting up logging...")
        version = self.config.get_runtime_version()
        logging_config = self.config.get_logging_config()
        for log_subscriber in logging_config:
            loglevels = log_subscriber.pop('loglevel', None)
            self.client.create_log_subscriber(log_subscriber)
            if version >= 6 and loglevels is not None:
                self.client.set_log_level({
                    "subscriber": log_subscriber['name'],
                    "nodes": [{'name': name, 'level': level}
                              for name, level in loglevels.items()],
                    "force": True,
                })
        self.client.start_logging()

    def _send_jetty_config(self):
        jetty_opts = self.config.get_jetty_options()
        if jetty_opts:
            logger.debug("Sending Jetty configuration...")
            self.client.set_jetty_options(jetty_opts)

    def _send_mime_types(self):
        mime_types = self.config.get_mimetypes()
        if mime_types:
            logger.debug("Sending mime types...")
            self.client.add_mime_type(mime_types)

    def send_runtime_config(self):
        config = copy.deepcopy(self.config.get_runtime_config())

        constants_to_use, _, _ = self.config.get_constants()
        config['MicroflowConstants'] = constants_to_use

        # convert MyScheduledEvents from list to dumb comma separated string if
        # needed:
        if isinstance(config.get('MyScheduledEvents', None), list):
            logger.trace("Converting mxruntime MyScheduledEvents from list to "
                         "comma separated string...")
            config['MyScheduledEvents'] = ','.join(config['MyScheduledEvents'])

        # convert certificate options from list to dumb comma separated string
        # if needed:
        for option in ('CACertificates', 'ClientCertificates',
                       'ClientCertificatePasswords'):
            if isinstance(config.get(option, None), list):
                logger.trace("Converting mxruntime %s from list to comma "
                             "separated string..." % option)
                config[option] = ','.join(config[option])

        logger.debug("Sending MxRuntime configuration...")
        self.client.update_configuration(config)

    def set_log_level(self, subscriber, node, level, timeout=None):
        params = {"subscriber": subscriber, "node": node, "level": level}
        return self.client.set_log_level(params, timeout=timeout)

    def get_log_levels(self, timeout=None):
        return self.client.get_log_settings({"sort": "subscriber"}, timeout=timeout)

    def has_license(self):
        return 'license' in self.client.get_license_information()

    def save_ddl_commands(self, ddl_commands):
        query_file_name = os.path.join(self.config.get_database_dump_path(),
                                       "%s_database_commands.sql" %
                                       time.strftime("%Y%m%d_%H%M%S"))
        logger.info("Saving DDL commands to %s" % query_file_name)
        with codecs.open(query_file_name, mode='w', encoding='utf-8') as f:
            f.write('\n'.join(ddl_commands))

    def unpack(self, mda_name):
        util.unpack(self.config, mda_name)
        self.reload_config()
        post_unpack_hook = self.config.get_post_unpack_hook()
        if post_unpack_hook:
            util.run_post_unpack_hook(post_unpack_hook)

    def download_and_unpack_runtime(self, version, curl_opts=None):
        mxversion = MXVersion(version)
        url = self.config.get_runtime_download_url(mxversion)
        path = self.config.get_first_writable_mxjar_repo()
        if path is None:
            raise M2EEException("None of the locations specified in the mxjar_repo "
                                "configuration option are writable by the current "
                                "user account.")
        util.download_and_unpack_runtime_curl(version, url, path, curl_opts)
        self.reload_config()

    def list_installed_runtimes(self):
        runtimes_path = self.config.get_first_writable_mxjar_repo()
        return util.list_installed_runtimes(runtimes_path)

    def cleanup_runtimes_except(self, versions):
        current_version = self.config.get_runtime_version()
        if current_version is not None:
            versions.append(current_version)
        runtimes_path = self.config.get_first_writable_mxjar_repo()
        util.cleanup_runtimes_except(versions, runtimes_path)
