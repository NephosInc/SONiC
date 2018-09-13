#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2018 Nephos, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import time
import subprocess
import re
import logging
import logging.handlers
import imp
import operator
import timeit
import signal
import threading
import json
import shutil
from functools import wraps

# python version
if sys.version > '3':
    PY3 = True
    import queue
else:
    PY3 = False
    import Queue as queue

# user should input polling frequency and confirm to run monitor(for debug)
DEBUG_MODE = False

# default polling frequency
KEY_MONITOR_USER_CFG_PERIOD = 'MONITOR_PERIOD'

# default numbers of sfp monitor worker
KEY_MONITOR_USER_CFG_WORKER_NUMBER = 'WORKER_NUMBER'

# run monitor as service mode
KEY_MONITOR_USER_CFG_SERVICE_MODE = 'SERVICE_MODE'

# logging level
KEY_MONITOR_USER_CFG_LOGGING_LEVEL = 'LOGGING_LEVEL'
g_sfp_logger = None
LOGGING_FILE_PATH = '/var/log/sfp_monitor.log'
LOGGING_FILE_SIZE = 5
LOGGING_FILE_ROTATING_NUM = 20

# ports in mask list will not be monitored
KEY_MONITOR_USER_CFG_MASK_PORTS = 'MASK_PORT_LIST'

# auto save dyanmic pre-emphasis config enable
KEY_MONITOR_USER_CFG_AUTO_SAVE = 'AUTO_SAVE'

# monitor user config file
MONITOR_USER_CFG_FILE_NAME = 'sfp_monitor.cfg'

# process stop running flag
_g_process_exit = False


def get_sfp_logging_level_map():
    level_map = {'DEBUG': logging.DEBUG,
                 'INFO': logging.INFO,
                 'WARNING': logging.WARNING,
                 'CRITICAL': logging.CRITICAL,
                 'ERROR': logging.ERROR}
    return level_map


def init_logging(logging_level=logging.DEBUG):
    global g_sfp_logger

    logger_name = 'sfp_monitor_logger'
    g_sfp_logger = logging.getLogger(logger_name)
    g_sfp_logger.setLevel(logging_level)

    # create file handler
    log_file_name = LOGGING_FILE_PATH
    fh = logging.handlers.RotatingFileHandler(log_file_name, mode='a+', maxBytes=LOGGING_FILE_SIZE * 1024 * 1024,
                                              backupCount=LOGGING_FILE_ROTATING_NUM, delay=0)
    fh.setLevel(logging_level)

    # create formatter
    fmt = "%(asctime)-15s %(levelname)s %(filename)s %(lineno)d %(funcName)s %(message)s"
    datefmt = "%a %d %b %Y %H:%M:%S"
    formatter = logging.Formatter(fmt, datefmt)

    # add handler and formatter to _sys_logger
    fh.setFormatter(formatter)
    g_sfp_logger.addHandler(fh)


def set_sfp_logging_level(level):
    global g_sfp_logger

    if g_sfp_logger.level != level:
        g_sfp_logger.setLevel(level)

    return True


# platform path
PLATFORM_ROOT_PATH = '/usr/share/sonic/device'
PLATFORM_PLUGINS = 'plugins'
PLATFORM_SPECIFIC_MODULE_NAME = 'sfputil'
PLATFORM_SPECIFIC_CLASS_NAME = "SfpUtil"

# Global platform-specific sfputil class instance
g_platform_sfputil = None

# port config file path
PORT_MAP_FILE_NAME = 'port_map.ini.'
PORT_CFG_FILE_NAME = 'port_config.ini'
PORT_CFG_NPS_FILE_NAME = 'port_config.nps'

# pre emphasis config filename extension
PRE_EMPHASIS_FILENAME_EXT = '.dsh'

# nephos default pre-emphasis config file name
DEFAULT_PRE_EMPHASIS_OPT_CFG_FILE_NAME = 'nephos_opt' + PRE_EMPHASIS_FILENAME_EXT
DEFAULT_PRE_EMPHASIS_DAC_CFG_FILE_NAME = 'nephos_dac' + PRE_EMPHASIS_FILENAME_EXT

"""
#global port info dict
#key:physical port
#value:{
        'user_port':{name:{
                            'lanes':{lane:{'eth_macro':dd,'lane':dd}},
                            'alias':'',
                            'nps_port':(unit, port)
                            'speed':dd
                            'media':'XRd'}
                            'mdio':{(devad, addr):value}}
        'present_sfp_info':{'Vendor Name':'', 
                    'Vendor PN':'', 
                    'Identifier':'', 
                    'Connector':''
                    'Complance Code'},
        'pre_emphasis':{(sfp info key):{(unit, nps port, lane count, property): data)
                }}
        }        
"""
g_phy_port_info = dict()


def KEY_PHY_PORT_INFO(phy_port):
    return str(phy_port)


KEY_PHY_PORT_INFO_V_USER_PORT = 'user_port'


def KEY_PHY_PORT_INFO_V_USER_PORT_V(port_name):
    return str(port_name)


KEY_PHY_PORT_INFO_V_USER_PORT_V_ALIAS = 'alias'
KEY_PHY_PORT_INFO_V_USER_PORT_V_LANES = 'lanes'
KEY_PHY_PORT_INFO_V_USER_PORT_V_NPS_PORT = 'nps_port'
KEY_PHY_PORT_INFO_V_USER_PORT_V_SPEED = 'speed'
KEY_PHY_PORT_INFO_V_USER_PORT_V_MEDIA = 'media'
KEY_PHY_PORT_INFO_V_USER_PORT_V_MDIO = 'mdio'


def KEY_PHY_PORT_INFO_V_USER_PORT_V_LANES_V(lane):
    return str(lane)


KEY_PHY_PORT_INFO_V_USER_PORT_V_LANES_V_ETH_MACRO = 'eth_macro'
KEY_PHY_PORT_INFO_V_USER_PORT_V_LANES_V_LANE = 'lane'
KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO = 'present_sfp_info'
KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_VENDOR_NAME = 'Vendor Name'
KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_VENDOR_PN = 'Vendor PN'
KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_IDENTIFIER = 'Identifier'
KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_CONNECTOR = 'Connector'
KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_COMPLIANCE_CODE = 'Specification compliance'
KEY_PHY_PORT_INFO_V_PRE_EMPHASIS = 'pre_emphasis'

g_platform_name = ''
g_hwsku_name = ''


def get_key_fuzzy_match_in_obj(key_str, obj):
    """
    case and space ignore match
    :param key_str: a string key
    :param obj: iterable obj
    :return:
    """
    key_slice = str(key_str).lower().split(' ')
    pt = re.compile(r'[\s\-_~.!@#%$&]*'.join(key_slice))

    for key in obj:
        if pt.search(key.lower()) is not None:
            return key
    return None


def KEY_PHY_PORT_INFO_V_PRE_EMPHASIS_V(sfp_info):
    key = []
    if KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_VENDOR_NAME in sfp_info:
        key.append(sfp_info[KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_VENDOR_NAME].lower())
    if KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_VENDOR_PN in sfp_info:
        key.append(sfp_info[KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_VENDOR_PN].lower())

    return tuple(key)


def KEY_PHY_PORT_INFO_V_PRE_EMPHASIS_V_V(unit, nps_port, lane_cnt, property_data):
    return tuple([str(unit), str(nps_port), str(lane_cnt), str(property_data)])


"""
key:(eth-macro, lane)
vlaue:{
    'nps_port':(unit, nps port)
    'phy_port':phy port
    }
"""
g_macro_lane_info = dict()


def KEY_MACRO_LANE_INFO(eth_macro, lane):
    return tuple([str(eth_macro), str(lane)])


KEY_MACRO_LANE_INFO_V_NPS_PORT = 'nps_port'
KEY_MACRO_LANE_INFO_V_PHY_PORT = 'phy_port'

"""
key: (unit, nps port)
value:{
        'eth-macro':macro
        'lane':lane
        'speed':speed
        'plane':plane
        'ppid':ppid
    }
"""
g_nps_port_info = dict()


def KEY_NPS_PORT_INFO(unit, nps_port):
    return tuple([str(unit), str(nps_port)])


KEY_NPS_PORT_INFO_V_ETH_MACRO = 'eth_macro'
KEY_NPS_PORT_INFO_V_LANE = 'lane'
KEY_NPS_PORT_INFO_V_SPEED = 'speed'
KEY_NPS_PORT_INFO_V_PLANE = 'plane'
KEY_NPS_PORT_INFO_V_PPID = 'ppid'

# global running config
g_running_config = {
    KEY_MONITOR_USER_CFG_PERIOD: 5,
    KEY_MONITOR_USER_CFG_WORKER_NUMBER: 1,
    KEY_MONITOR_USER_CFG_SERVICE_MODE: 1,
    KEY_MONITOR_USER_CFG_LOGGING_LEVEL: logging.INFO,
    KEY_MONITOR_USER_CFG_MASK_PORTS: [],
    KEY_MONITOR_USER_CFG_AUTO_SAVE: 1
}


def get_global_running_config(k=None):
    global g_running_config

    if k is None:
        return g_running_config
    elif k in g_running_config:
        return g_running_config[k]
    else:
        return None


def set_global_running_config(k_v_dict):
    global g_running_config

    if type(k_v_dict) is not dict:
        return False

    k_running = set(g_running_config.keys())
    k_para = set(k_v_dict.keys())
    if (k_running & k_para) == k_para:
        g_running_config.update(k_v_dict)

    return True


def _get_platform_and_hwsku():
    """
    get hardware sku
    :return: (platform, hwsku)
    """
    global g_platform_name
    global g_hwsku_name

    if g_platform_name != '' and g_hwsku_name != '':
        return g_platform_name, g_hwsku_name

    platform = ""
    hwsku = ""
    cmd = ['show', 'platform', 'summary']
    cmd_out = subprocess.check_output(cmd)
    g_sfp_logger.debug(cmd_out)
    pt = re.compile(r'^Platform:\s*([^\n\r\b]*).*HwSKU\s*:\s*([^\n\r\b]*)', re.I | re.M | re.S)
    result = pt.search(cmd_out)
    if result is not None:
        g_sfp_logger.debug("type result:{}, result:{}\nmatch:{}\n".format(type(result), result, result.group()))
        platform = result.group(1)
        hwsku = result.group(2)

    if platform == "":
        cmd = ['show', 'platform', 'syseeprom']
        cmd_out = subprocess.check_output(cmd)
        g_sfp_logger.debug(cmd_out)
        pt = re.compile(r'^Platform\s+Name\s+\w+\s+\d+\s+([^\n\r\b]*)', re.I | re.M | re.S)
        result = pt.search(cmd_out)
        if result is not None:
            g_sfp_logger.debug("type result:{}, result:{}\nmatch:{}\n".format(type(result), result, result.group()))
            platform = result.group(1)

    g_platform_name, g_hwsku_name = platform, hwsku
    return platform, hwsku


def _get_path_to_platform_hwsku():
    """
    Returns path to platform and hwsku
    :return: (path to platform, path to hwsku)
    """
    # Get platform and hwsku
    (platform, hwsku) = _get_platform_and_hwsku()

    # Load platform module from source
    platform_path = "/".join([PLATFORM_ROOT_PATH, platform])
    hwsku_path = "/".join([platform_path, hwsku])

    return platform_path, hwsku_path


def _load_platform_sfputil():
    """
    Loads platform specific sfputil module from source
    :return:
    """
    global g_platform_sfputil

    # Get platform and hwsku path
    (platform_path, hwsku_path) = _get_path_to_platform_hwsku()

    try:
        module_file = "/".join([platform_path, PLATFORM_PLUGINS, PLATFORM_SPECIFIC_MODULE_NAME + ".py"])
        module = imp.load_source(PLATFORM_SPECIFIC_MODULE_NAME, module_file)
    except IOError as e:
        g_sfp_logger.error("Failed to load platform module '%s': %s" % (PLATFORM_SPECIFIC_MODULE_NAME, str(e)))
        return -1

    try:
        platform_sfputil_class = getattr(module, PLATFORM_SPECIFIC_CLASS_NAME)
        g_platform_sfputil = platform_sfputil_class()

        # overwride _sfp_eeprom_present of baseclass for performance
        def wrap_sfp_eeprom_present(sysfs_sfp_i2c_client_eeprompath, offset):
            return True

        g_platform_sfputil._sfp_eeprom_present = wrap_sfp_eeprom_present
    except AttributeError as e:
        g_sfp_logger.error("Failed to instantiate '%s' class: %s\n" % (PLATFORM_SPECIFIC_CLASS_NAME, str(e)))
        return -2

    return 0


def _get_path_to_port_config_file():
    """
    Returns path to port config file
    :return:
    """
    # Get platform and hwsku path
    (platform_path, hwsku_path) = _get_path_to_platform_hwsku()

    # First check for the presence of the new 'port_config.ini' file
    port_config_file_path = "/".join([hwsku_path, PORT_CFG_FILE_NAME])
    if not os.path.isfile(port_config_file_path):
        # port_config.ini doesn't exist. Try loading the legacy 'portmap.ini' file
        port_config_file_path = "/".join([hwsku_path, PORT_MAP_FILE_NAME])

    return port_config_file_path


def _get_path_to_monitor_user_config_file():
    """
    Returns path to monitor user config file
    :return:
    """
    # Get platform and hwsku path
    (platform_path, hwsku_path) = _get_path_to_platform_hwsku()

    # First check for the presence of the new 'port_config.ini' file
    config_file_path = "/".join([hwsku_path, MONITOR_USER_CFG_FILE_NAME])

    return config_file_path


def init_global_data():
    """
    clear all global data
    :return:
    """
    global g_platform_sfputil
    global g_phy_port_info
    global g_macro_lane_info
    global g_nps_port_info

    g_platform_sfputil = None

    g_phy_port_info.clear()
    g_macro_lane_info.clear()
    g_nps_port_info.clear()

    g_sfp_logger.debug("g_phy_port_info={}\n g_macro_lane_info={}\n g_nps_port_info= {}\n".format(
        g_phy_port_info, g_macro_lane_info, g_nps_port_info))
    return


def macro_lane_2_logic_lane(eth_macro, lane):
    return eth_macro * 4 + lane


def logic_lane_2_macro_lane(logic_lane):
    return logic_lane // 4, logic_lane % 4


def init_phy_port_macro_lane_mapping(port_config_file_path):
    """
    init phy port to (eth-group, lane) mapping from config file
    :param port_config_file_path:
    :return: None
    """
    global g_phy_port_info
    global g_macro_lane_info

    with open(port_config_file_path, mode='r') as f:
        config = f.read()

    # match content of port_config.ini:
    # Ethernet0       0,1,2,3           Ethernet1/1       0
    pat_string = r'^([\w/]+)\s+([\d,]+)\s+([\w/]+)\s+(\d+)'
    pat = re.compile(pat_string, re.M)
    result = pat.finditer(config)
    if result is None:
        g_sfp_logger.error("content of config file:{} is invalid\n".format(port_config_file_path))
        g_sfp_logger.debug("content of config file{}:\n{}\n".format(port_config_file_path, config))
        return False

    for m in result:
        # g_sfp_logger.debug("config file:{} match {}:".format(port_config_file_path, m.group(0)))
        user_port_name = m.group(1)
        logical_lanes = m.group(2)
        user_port_alias = m.group(3)
        phy_port = m.group(4)

        # phy_port_info->value
        k = KEY_PHY_PORT_INFO(phy_port)
        if k not in g_phy_port_info:
            g_phy_port_info[k] = dict()
        phy_port_info_value = g_phy_port_info[k]

        # phy_port_info->value->user_port->value
        k = KEY_PHY_PORT_INFO_V_USER_PORT
        if k not in phy_port_info_value:
            phy_port_info_value[k] = dict()
        all_user_port_value = phy_port_info_value[k]

        # get phy_port_info->value->user_port->value->(port_name)->value
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V(user_port_name)
        if k not in all_user_port_value:
            all_user_port_value[k] = dict()
        cur_user_port_value = all_user_port_value[k]

        # update phy_port_info->value->user_port->value->(port_name)->value->alias->value
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V_ALIAS
        if k not in cur_user_port_value:
            cur_user_port_value[k] = user_port_alias

        # get phy_port_info->value->user_port->value->(port_name)->value->lanes->value
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V_LANES
        if k not in cur_user_port_value:
            cur_user_port_value[k] = dict()
        cur_usr_port_lanes_value = cur_user_port_value[k]

        logical_lane_list = logical_lanes.split(',')
        for ll in logical_lane_list:
            eth_macro, lane = logic_lane_2_macro_lane(int(ll))
            eth_macro = str(eth_macro)
            lane = str(lane)

            # update (macro, lane) -> phy_port mapping of g_macro_lane_info
            k = KEY_MACRO_LANE_INFO(eth_macro, lane)
            if k not in g_macro_lane_info:
                g_macro_lane_info[k] = dict()
            macro_lane_info_value = g_macro_lane_info[k]
            dict_tmp = {KEY_MACRO_LANE_INFO_V_PHY_PORT: phy_port}
            macro_lane_info_value.update(dict_tmp)

            # update phy_port_info->value->user_port->value->(port_name)->value->lanes->value
            k = KEY_PHY_PORT_INFO_V_USER_PORT_V_LANES_V(ll)
            cur_usr_port_lanes_value[k] = {KEY_PHY_PORT_INFO_V_USER_PORT_V_LANES_V_ETH_MACRO: eth_macro,
                                           KEY_PHY_PORT_INFO_V_USER_PORT_V_LANES_V_LANE: lane}

    g_sfp_logger.debug("g_phy_port_info:{}\n g_macro_lane_info:{}\n".format(
        g_phy_port_info, g_macro_lane_info))

    return True


def _get_sys_nps_port_macro_lane_mapping():
    """
    run npx_diag cmd to get nps_port and macro lane mapping
    :return:
    """

    # get nps_port to macro and lane mapping
    # unit/port eth-macro lane max-speed act gua bin plane hw-mac tm-mac mpid ppid
    #   0/  0        0    0    100000   1   0   0     1    16     0     0     0
    cmd = ['npx_diag', 'diag show info port']
    mapping_str_buffer = subprocess.check_output(cmd)
    g_sfp_logger.debug("npx_diag = {}\n".format(mapping_str_buffer))

    return mapping_str_buffer


def init_nps_port_macro_lane_mapping(mapping_str_buffer):
    """
    init g_nps_port_info from mapping_str
    :param mapping_str_buffer:
    :return:
    """
    global g_macro_lane_info
    global g_nps_port_info

    # init g_nps_port_info
    # unit/port eth-macro lane max-speed act gua bin plane hw-mac tm-mac mpid ppid
    #   0/  0        0    0    100000   1   0   0     1    16     0     0     0
    pr_str = r'''^\s+(?P<unit>\d+)\s*/\s*(?P<port>\d+)\s+   #0/0
            (?P<macro>\d+)\s+   #eth-macro
            (?P<lane>\d+)\s+    #lane
            (?P<speed>\d+)\s+   #max-speed
            \d+\s+  #act
            \d+\s+  #gua
            \d+\s+  #bin
            (?P<plane>\d+)\s+   #plane
            \d+\s+  #hw-mac
            \d+\s+  #tm-mac
            \d+\s+  #mpid
            (?P<ppid>\d+)   #ppid
            .*$'''
    pat = re.compile(pr_str, re.I | re.M | re.X)
    result = pat.finditer(mapping_str_buffer)
    if result is None:
        g_sfp_logger.error("invalid mapping_str_buffer\n")
        return False

    for p in result:
        # g_sfp_logger.debug("match:{}".format(p.group(0)))
        unit = p.group('unit')
        port = p.group('port')
        eth_macro = p.group('macro')
        lane = p.group('lane')

        # update macro,lane values of nps port in g_nps_port_info
        k = KEY_NPS_PORT_INFO(unit, port)
        if k not in g_nps_port_info:
            g_nps_port_info[k] = dict()
        dict_tmp = {KEY_NPS_PORT_INFO_V_ETH_MACRO: eth_macro,
                    KEY_NPS_PORT_INFO_V_LANE: lane,
                    KEY_NPS_PORT_INFO_V_SPEED: p.group('speed'),
                    KEY_NPS_PORT_INFO_V_PLANE: p.group('plane'),
                    KEY_NPS_PORT_INFO_V_PPID: p.group('ppid')}
        g_nps_port_info[k].update(dict_tmp)

        # update nps port value of (macro, lane) in g_macro_lane_info
        k = KEY_MACRO_LANE_INFO(eth_macro, lane)
        if k not in g_macro_lane_info:
            g_macro_lane_info[k] = dict()
        dict_tmp = {KEY_MACRO_LANE_INFO_V_NPS_PORT: (unit, port)}
        g_macro_lane_info[k].update(dict_tmp)

        # get phy port
        phy_port = g_macro_lane_info[k][KEY_MACRO_LANE_INFO_V_PHY_PORT]

        # get phy port info
        k = KEY_PHY_PORT_INFO(phy_port)
        phy_port_info_value = g_phy_port_info[k]

        # get phy_port_info->value->user_port
        k = KEY_PHY_PORT_INFO_V_USER_PORT
        all_user_port_value = phy_port_info_value[k]

        # find current nps port and update speed
        logic_lane = macro_lane_2_logic_lane(int(eth_macro), int(lane))
        for port_name, port_attr in all_user_port_value.items():
            if str(logic_lane) in port_attr[KEY_PHY_PORT_INFO_V_USER_PORT_V_LANES]:
                k = KEY_PHY_PORT_INFO_V_USER_PORT_V_SPEED
                all_user_port_value[port_name][k] = p.group('speed')

                k = KEY_PHY_PORT_INFO_V_USER_PORT_V_NPS_PORT
                all_user_port_value[port_name][k] = (unit, port)
                break

    g_sfp_logger.debug("g_nps_port_info:{}\n g_macro_lane_info:{}\n".format(
        g_nps_port_info, g_macro_lane_info))
    return True


def _get_pre_emphasis_config_filelist(pre_emphasis_config_file_path):
    """
    get pre emphasis config file list form pre_emphasis_config_file_path
    :return: 0 for sucess, none zero for failure
    """
    pre_emphasis_config_file_list = []
    file_list = os.listdir(pre_emphasis_config_file_path)
    for i in range(0, len(file_list)):
        f = file_list[i]
        f_path = os.path.join(pre_emphasis_config_file_path, f)
        if os.path.isfile(f_path):
            if os.path.splitext(f)[1] == PRE_EMPHASIS_FILENAME_EXT:
                pre_emphasis_config_file_list.append(file_list[i])

    return pre_emphasis_config_file_path, pre_emphasis_config_file_list


def init_phy_port_sfp_pre_emphasis_config_file(config_file):
    """
    init pre-emphasis of phy port from dsh config_file
    :param config_file:
    :return:
    """
    global g_phy_port_info
    global g_nps_port_info
    global g_macro_lane_info

    file_path = config_file[0]
    file_name = config_file[1]

    fp = os.path.join(file_path, file_name)
    key_split = os.path.splitext(file_name)[0].split('_')
    if len(key_split) < 2:
        g_sfp_logger.error("(sfp vendor name)_(sfp vendor pn).preem config file name expected:{}\n".format(
            file_name))
        return -1

    sfp_info = {KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_VENDOR_NAME: key_split[0].lower(),
                KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_VENDOR_PN: key_split[1].lower()}
    sfp_pre_emphasis_key = KEY_PHY_PORT_INFO_V_PRE_EMPHASIS_V(sfp_info)

    # content of pre-emphasis config file:
    # phy set pre-emphasis unit=0 portlist=0 lane-cnt=4 property=cn1 data=0x01.01.01.01
    with open(fp, mode='r') as f:
        config_content = f.read()
        pat_str = r'''^phy\s+set\s+pre-emphasis\s+     #phy set pre-emphasis
                ([\w]+\s*=\s*(?P<unit>\d+)\s+){0,1}   #unit=0 
                [\w]+\s*=\s*(?P<portlist>[\d\-]+)\s+  #portlist=0
                [\w\-]+\s*=\s*(?P<lane_cnt>\d+)\s+ #lane-cnt=4
                [\w]+\s*=\s*(?P<property>\w+)\s+    #property=cn1
                [\w]+\s*=\s*(?P<data>[\w\.]+)   #data=0x01.01.01.01
                .*$
                '''
        pat = re.compile(pat_str, re.M | re.I | re.X)
        result = pat.finditer(config_content)
        if result is None:
            g_sfp_logger.error("config file:{} has no valid pre-emphasis configuration data\n".format(file_name))
            g_sfp_logger.debug("content of config file {}:{}\n".format(file_name, config_content))
            return -2

        for pre in result:
            # g_sfp_logger.debug("config file {} content match:{}".format(file_name, pre.group(0)))
            unit = pre.group('unit')
            if unit is None:
                unit = 0
            nps_port = pre.group('portlist')
            lane_cnt = pre.group('lane_cnt')
            property_data = pre.group('property')
            data = pre.group('data')
            data_hl = [hex(y)[2:] for y in [int(x, 16) for x in data.split('.')]]
            if int(lane_cnt) != len(data_hl):
                g_sfp_logger.error("incorrect pre-emphasis value:{}\n".format(pre.group(0)))
                continue

            # get first logic_lane number from (unit, nps_port)
            k = KEY_NPS_PORT_INFO(unit, nps_port)
            if k not in g_nps_port_info:
                g_sfp_logger.error("(unit,port){} is not in g_nps_port_info\n".format((unit, nps_port)))
                continue
            eth_macro, lane = g_nps_port_info[k][KEY_NPS_PORT_INFO_V_ETH_MACRO], g_nps_port_info[k][
                KEY_NPS_PORT_INFO_V_LANE]
            logic_lane_start = macro_lane_2_logic_lane(int(eth_macro), int(lane))

            # get phy_port:[(unit, nps_port), lane_cnt, data_offset] map to support port aggregate
            # pre-emphasis configuration
            # get first logic_lane number from (unit, nps_port)
            phy_port_data_map = dict()
            for logic_lane in range(logic_lane_start, logic_lane_start + int(lane_cnt)):
                eth_macro, lane = logic_lane_2_macro_lane(logic_lane)
                eth_macro = str(eth_macro)
                lane = str(lane)

                # get phy port
                k = KEY_MACRO_LANE_INFO(eth_macro, lane)
                if k not in g_macro_lane_info:
                    g_sfp_logger.error("{} is not in g_macro_lane_info {}\n".format(k, g_macro_lane_info))
                    continue
                if KEY_MACRO_LANE_INFO_V_PHY_PORT not in g_macro_lane_info[k]:
                    g_sfp_logger.error(
                        "g_macro_lane_info of {} has no phy port member\n".format(g_macro_lane_info[k]))
                    continue
                phy_port = g_macro_lane_info[k][KEY_MACRO_LANE_INFO_V_PHY_PORT]
                if phy_port in phy_port_data_map:
                    phy_port_data_map[phy_port][1] += 1
                else:
                    if KEY_MACRO_LANE_INFO_V_NPS_PORT not in g_macro_lane_info[k]:
                        g_sfp_logger.error("g_macro_lane_info of {} has no nps port member\n".format(
                            g_macro_lane_info[k]))
                        continue
                    nps_port = g_macro_lane_info[k][KEY_MACRO_LANE_INFO_V_NPS_PORT]
                    phy_port_data_map[phy_port] = [nps_port, 1, logic_lane - logic_lane_start]

            # update phy port sfp pre emphasis
            for phy_port, data_map in phy_port_data_map.items():
                k = KEY_PHY_PORT_INFO(phy_port)
                if k not in g_phy_port_info:
                    g_sfp_logger.error("phy_port{} is not in g_phy_port_info\n".format(k))
                    continue
                if KEY_PHY_PORT_INFO_V_PRE_EMPHASIS not in g_phy_port_info[k]:
                    g_phy_port_info[k][KEY_PHY_PORT_INFO_V_PRE_EMPHASIS] = dict()
                pre_emphasis_value = g_phy_port_info[k][KEY_PHY_PORT_INFO_V_PRE_EMPHASIS]
                if sfp_pre_emphasis_key not in pre_emphasis_value:
                    pre_emphasis_value[sfp_pre_emphasis_key] = dict()
                sfp_pre_emphasis_value = pre_emphasis_value[sfp_pre_emphasis_key]
                k = KEY_PHY_PORT_INFO_V_PRE_EMPHASIS_V_V(data_map[0][0], data_map[0][1], str(data_map[1]),
                                                         property_data)
                sfp_pre_emphasis_value.update({k: '0x' + '.'.join(data_hl[data_map[2]:data_map[2] + data_map[1]])})
        g_sfp_logger.debug("initiated file {} g_phy_port_info={}\n".format(file_name, g_phy_port_info))

    return 0


def init_phy_port_sfp_pre_emphasis_config(config_file_list):
    """
    traverse all (spf_vendor_name)_(sfp_vendor_pn).dsh pre-emphasis config files in hwsku specific dir,
    and init (phy_port, sfp, pre-emphasis) mapping in g_phy_port_info
    :return:0 for sucess, none zero for failure
    """
    ret = 0

    config_file_path = config_file_list[0]
    config_file_names = config_file_list[1]

    if len(config_file_names) == 0:
        g_sfp_logger.error("0 file in config_file_list.\n")
        return -1

    for config_file in config_file_names:
        ret_one_file = init_phy_port_sfp_pre_emphasis_config_file((config_file_path, config_file))
        if ret_one_file != 0:
            ret = -1

    return ret


def _valid_global_data():
    global g_phy_port_info
    ret = 0

    for phy_port, phy_port_info in g_phy_port_info.items():
        if KEY_PHY_PORT_INFO_V_USER_PORT not in phy_port_info \
                or KEY_PHY_PORT_INFO_V_PRE_EMPHASIS not in phy_port_info:
            g_sfp_logger.error("invalid phy_port_info[{}] = {}\n".format(phy_port, phy_port_info))
            # pre-emphasis error
            ret = -2
            continue

    return ret


def init():
    """
    load sfputil module from device and init port phy2logic config mapping
    :return:
    """
    global g_platform_sfputil

    g_sfp_logger.info("Initiation starting...\n")

    # only should be call one time and only should be call here
    init_global_data()

    # load sfputil module
    ret = _load_platform_sfputil()
    if 0 != ret:
        g_sfp_logger.error("_load_platform_sfputil fail({})\n")
        return ret

    # init phy port to sonic logical port mappnig of g_platform_sfputil
    try:
        port_config_file_path = _get_path_to_port_config_file()
        g_platform_sfputil.read_porttab_mappings(port_config_file_path)
    except Exception as e:
        g_sfp_logger.error("read port config file fail({})".format(str(e)))
        return -1

    # init phy port to (macro,lane) mapping
    try:
        init_phy_port_macro_lane_mapping(port_config_file_path)
    except Exception as e:
        g_sfp_logger.error("init_phy_port_macro_lane_mapping fail({})\n".format(str(e)))
        return -2

    # init nps port to (macro, lane) mapping
    try:
        mapping_str_buffer = _get_sys_nps_port_macro_lane_mapping()
        init_nps_port_macro_lane_mapping(mapping_str_buffer)
    except Exception as e:
        g_sfp_logger.error("init_nps_port_macro_lane_mapping fail({})\n".format(str(e)))
        return -3

    # init phy port pre-emphasis configuration
    try:
        (platform_path, hwsku_path) = _get_path_to_platform_hwsku()
        config_file_list = _get_pre_emphasis_config_filelist(hwsku_path)
        init_phy_port_sfp_pre_emphasis_config(config_file_list)
    except Exception as e:
        g_sfp_logger.error("init_phy_port_sfp_pre_emphasis_config fail({})\n".format(str(e)))
        return -4

    ret = _valid_global_data()
    if ret != 0:
        return -5

    g_sfp_logger.info("Initiation done.\n")

    return 0


def decro_timeit(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        worker_id = threading.current_thread().name
        t0 = timeit.default_timer()
        ret = func(*args, **kwargs)
        t1 = timeit.default_timer()
        g_sfp_logger.info('of worker {} {} cost time: {}s\n'.format(
            func.__name__, worker_id, t1 - t0))
        g_sfp_logger.debug('args: {}s\n'.format(list(args) + list(kwargs)))

        return ret

    return wrapper


def decro_get_docker_exec(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        cmd = ['docker', 'exec', '-i', 'syncd', 'bash']
        popen_obj = subprocess.Popen(cmd, bufsize=1024 * 1024, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
        exec_cmd = func(popen_obj, *args, **kwargs)
        cmd_out = popen_obj.communicate()
        if cmd_out[1] != '':
            # cmd exec fail
            g_sfp_logger.error("cmd={} type cmd_out {}, cmd_out:{}\n".format(exec_cmd, type(cmd_out), cmd_out))
            return -1, exec_cmd, ''
        else:
            return 0, exec_cmd, cmd_out[0]

    return wrapper


@decro_timeit
def get_port_sfp_present_status(phy_port):
    """
    get sfp present status of port
    :param phy_port:
    :return: True if present
    """
    global g_platform_sfputil

    present = g_platform_sfputil.get_presence(phy_port)

    return present


def get_phy_port_info(phy_port_info_dict, phy_port):
    k = KEY_PHY_PORT_INFO(phy_port)
    if k in phy_port_info_dict.keys():
        return phy_port_info_dict[k]
    else:
        g_sfp_logger.error("key phy port {} is not in phy_port_info_dict\n".format(k))
        return dict()


def get_phy_user_port_list(phy_port_info):
    k = KEY_PHY_PORT_INFO_V_USER_PORT
    if k not in phy_port_info:
        g_sfp_logger.error("key {} is not in {}\n".format(k, phy_port_info))
        return {}
    return phy_port_info[k]


@decro_timeit
def get_port_sfp_info(phy_port):
    """
    get eeprom sfp dict info from sfp moudule
    :param phy_port:phy_port
    :return: a sfp info dict
    """
    global g_platform_sfputil
    sfp_info_data = {}

    sfp_info_eeprom = g_platform_sfputil.get_eeprom_dict(phy_port)
    if sfp_info_eeprom is None:
        g_sfp_logger.error("can't read sfp info of phy port {}\n".format(phy_port))
        return sfp_info_data

    # vendor info, ref SFF-8024 Transceiver Management
    if ('interface' not in sfp_info_eeprom) or ('data' not in sfp_info_eeprom['interface']):
        g_sfp_logger.error("unknown sfp info {} of phy port {}\n".format(sfp_info_data, phy_port))
        return sfp_info_data

    pat = re.compile(r'\s+')
    sp_replace = '-'
    sfp_info_eeprom_data = sfp_info_eeprom['interface']['data']
    k = KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_VENDOR_NAME
    fuzzy_key = get_key_fuzzy_match_in_obj(k, sfp_info_eeprom_data)
    if fuzzy_key is not None:
        sfp_info_data[k] = pat.sub(sp_replace, sfp_info_eeprom_data[fuzzy_key]).lower()
    else:
        g_sfp_logger.info("unknown sfp vendor name {} of phy port {}\n".format(sfp_info_data, phy_port))
        sfp_info_data[k] = 'unknown'

    k = KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_VENDOR_PN
    fuzzy_key = get_key_fuzzy_match_in_obj(k, sfp_info_eeprom_data)
    if fuzzy_key is not None:
        sfp_info_data[k] = pat.sub(sp_replace, sfp_info_eeprom_data[fuzzy_key]).lower()
    else:
        g_sfp_logger.info("unknown sfp vendor pn {} of phy port {}\n".format(sfp_info_data, phy_port))
        sfp_info_data[k] = 'unknown'

    k = KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_IDENTIFIER
    fuzzy_key = get_key_fuzzy_match_in_obj(k, sfp_info_eeprom_data)
    if fuzzy_key is not None:
        sfp_info_data[k] = pat.sub('', sfp_info_eeprom_data[fuzzy_key]).lower()
    else:
        g_sfp_logger.info("unknown sfp identifier {} of phy port {}\n".format(sfp_info_data, phy_port))
        sfp_info_data[k] = 'unknown'

    k = KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_CONNECTOR
    fuzzy_key = get_key_fuzzy_match_in_obj(k, sfp_info_eeprom_data)
    if fuzzy_key is not None:
        sfp_info_data[k] = pat.sub('', sfp_info_eeprom_data[fuzzy_key]).lower()
    else:
        g_sfp_logger.info("unknown sfp connector {} of phy port {}\n".format(sfp_info_data, phy_port))
        sfp_info_data[k] = 'unknown'

    # {'10/40G Ethernet Compliance Code': '40GBASE-CR4'}
    k = KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_COMPLIANCE_CODE
    fuzzy_key = get_key_fuzzy_match_in_obj(k, sfp_info_eeprom_data)
    if fuzzy_key is not None:
        sfp_info_data[k] = str(sfp_info_eeprom_data[fuzzy_key]).lower()
    else:
        g_sfp_logger.info("unknown sfp specification compliance {} of phy port {}\n".format(sfp_info_data,
                                                                                            phy_port))
        sfp_info_data[k] = 'unknown'

    return sfp_info_data


def get_sfp_type(sfp_info):
    """
    get sfp type from sfp eeprom info
    :param sfp_info:
    :return: 'DAC'--copper; 'OPT'--fiber
    """
    dac_connector_dict = {'copperpigtail': 'DAC', "noseparableconnector": 'DAC'}

    k = KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_CONNECTOR
    if k in sfp_info:
        connector_value = str(sfp_info[k]).lower().replace(' ', '')
        if connector_value in dac_connector_dict:
            return dac_connector_dict[connector_value]

    return 'OPT'


def get_sfp_compliance_code_abbr(sfp_info):
    media_abbr = []

    k = KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO_COMPLIANCE_CODE
    if k in sfp_info:
        pt_str = r'.*-(?P<media_base>[ceskl]r)(?P<media_cnt>\d*)\s*'
        pt = re.compile(pt_str, re.I)
        result = pt.search(sfp_info[k])
        if result is not None:
            media_abbr = ['sfp', result.group('media_base')]
            if result.group('media_cnt') == '':
                media_abbr.append(1)
            else:
                media_abbr.append(result.group('media_cnt'))
        else:
            g_sfp_logger.info("can't find compliance code abbr in {}\n".format(sfp_info))

    if len(media_abbr) == 0:
        sfp_media_type = get_sfp_type(sfp_info)
        if 'OPT' == sfp_media_type:
            media_abbr = ['default', 'sr', '']
        else:
            media_abbr = ['default', 'cr', '']

    return media_abbr


def init_phy_port_media_mdio_config(phy_port_info, sfp_info):
    """
    init all user ports' media of a phy port
    :param phy_port_info:
    :param sfp_info:
    :return:
    """

    # get phy_port_info->value->user_port
    k = KEY_PHY_PORT_INFO_V_USER_PORT
    all_user_port_value = phy_port_info[k]
    user_port_cnt = len(all_user_port_value)

    # sfp support 1 or x sub ports, x is defined by x in cr[x]
    media_abbr = get_sfp_compliance_code_abbr(sfp_info)
    if media_abbr[0] == 'default':
        sfp_support_break_port_nums = [1, user_port_cnt]
    else:
        sfp_support_break_port_nums = [1, int(media_abbr[2])]
    if user_port_cnt not in sfp_support_break_port_nums:
        # wrong break port config
        g_sfp_logger.error("please check break port config of phy port {}\n".format(all_user_port_value))
        return -1

    if user_port_cnt == 1:
        media_value = ''.join(media_abbr[1:])
    else:
        media_value = media_abbr[1]

    # find current nps port and update speed
    for port in all_user_port_value:
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V_MEDIA
        all_user_port_value[port][k] = media_value

        # find current nps port and update mdio value
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V_MDIO
        if k not in all_user_port_value[port]:
            all_user_port_value[port][k] = dict()
        if 'OPT' == get_sfp_type(sfp_info):
            all_user_port_value[port][k].update({('0x1e', '0x2'): '0x8000'})
        else:
            all_user_port_value[port][k].update({('0x1e', '0x2'): '0x0'})

    return 0


def check_sfp_info_change(phy_port_info, sfp_info):
    k = KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO
    if k not in phy_port_info:
        phy_port_info[k] = dict()
    last_sfp_type_dict = phy_port_info[k]
    changed = operator.ne(last_sfp_type_dict, sfp_info)

    return changed


@decro_timeit
def get_phy_port_admin_status(user_port_list):
    """
    get port status of user logic ports
    :param user_port_list:
    :return:
    """
    port_admin_status = dict()

    cmd = ['show', 'interface', 'status']
    pcmd = subprocess.Popen(cmd, bufsize=-1, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cmd_out = pcmd.communicate()
    if cmd_out[1] != '':
        # cmd exec fail
        g_sfp_logger.error("cmd={} type cmd_out {}, cmd_out:{}\n".format(cmd, type(cmd_out), cmd_out))
        return -1, port_admin_status

    # Interface    Lanes    Speed    MTU         Alias    Oper    Admin
    # -----------  -------  -------  -----  ------------  ------  -------
    # Ethernet12       20      10G   9100  Ethernet13/1      up       up
    pt_str = r'''^\s* 
             (?P<port_name>({}))\s+  #interface 
             (?P<lanes>[\d,]+)\s+  #lanes 
             [\w/]+\s+  #speed 
             \d+\s+  #mtu 
             (?P<alias>[\w/]+)\s+ 
             [\w/]+\s+ 
             (?P<admin>[\w/]+) 
             .*$ 
             '''
    port_name_list = '{}'.format('|'.join(list(user_port_list)))
    pt_str = pt_str.format(port_name_list)
    pt = re.compile(pt_str, re.I | re.M | re.X)
    result = pt.finditer(cmd_out[0])
    if result is None:
        g_sfp_logger.error("port {} cmd={} search fail cmd_out={}\n".format(list(user_port_list),
                                                                            cmd, cmd_out[0]))
        return -1, port_admin_status

    for r in result:
        user_port = r.group('port_name')
        status = r.group('admin')
        port_admin_status[user_port] = status

    return 0, port_admin_status


@decro_timeit
def admin_up_user_ports(port_admin_status):
    """
    :param port_admin_status dict
    :return: shutdown all ports
    """
    ret = 0

    for user_port, admin in port_admin_status.items():
        if str(admin).lower() == 'up'.lower():
            cmd = ['ip', 'link', 'set', 'up', str(user_port)]
            pcmd = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            cmd_out = pcmd.communicate()
            if cmd_out[1] != '':
                # cmd exec fail
                g_sfp_logger.error("cmd={} type cmd_out {}, cmd_out:{}\n".format(cmd, type(cmd_out), cmd_out))
                ret = -1

    return ret


@decro_timeit
@decro_get_docker_exec
def npx_admin_down_user_ports(popen_obj, user_port_list):
    exec_cmd = []

    for port in user_port_list:
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V_NPS_PORT
        nps_port = user_port_list[port][k]
        cmd_str = 'npx_diag port set property unit={} portlist={} admin=disable'.format(
            nps_port[0], nps_port[1])
        popen_obj.stdin.write(cmd_str + '\n')
        exec_cmd.append(cmd_str)
        time.sleep(0.005)

    return exec_cmd


@decro_timeit
def admin_down_user_ports(port_admin_status, user_port_list):
    ret = 0

    for user_port, admin in port_admin_status.items():
        if str(admin).lower() == 'up'.lower():
            cmd = ['ip', 'link', 'set', 'down', str(user_port)]
            pcmd = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            cmd_out = pcmd.communicate()
            if cmd_out[1] != '':
                # cmd exec fail
                ret = -1
                g_sfp_logger.error("cmd={} type cmd_out {}, cmd_out:{} ret = {}\n".format(
                    cmd, type(cmd_out), cmd_out, ret))
    if 0 == ret:
        # wtf workaround
        ret, exec_cmd, cmd_out = npx_admin_down_user_ports(user_port_list)
        if 0 != ret:
            ret = -2

    if 0 != ret:
        ret_up = admin_up_user_ports(port_admin_status)
        if ret_up != 0:
            ret = -3
            g_sfp_logger.error("ret = {}\n".format(ret))

    return ret


def get_phy_port_sfp_specific_media(user_port_list):
    media_config = dict()

    for p in user_port_list:
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V_NPS_PORT
        nps_port = user_port_list[p][k]
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V_MEDIA
        media = user_port_list[p][k]
        media_config[nps_port] = media

    return media_config


def get_phy_port_sfp_specific_mdio(user_port_list):
    mdio_config = dict()

    for p in user_port_list:
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V_NPS_PORT
        nps_port = user_port_list[p][k]
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V_MDIO
        mdio = user_port_list[p][k]
        mdio_config[nps_port] = mdio

    return mdio_config


# config order should be C2 -> CN1 -> C1 -> C0
def my_udf_pre_emphasis_cmp(x, y):
    order_map = {'c0': 4, 'c1': 3, 'c2': 1, 'cn1': 2}
    return cmp(order_map[x], order_map[y])


@decro_timeit
def get_port_running_config_exec_cmd(popen_obj, pre_emphasis_config, user_port_list):
    exec_cmd = []

    # show media
    cmd_str = 'npx_diag port show property' + '\n'
    popen_obj.stdin.write(cmd_str)
    exec_cmd.append(cmd_str)
    time.sleep(0.005)

    # show pre-emphasis
    ordered_key_list = sorted(list(pre_emphasis_config), cmp=my_udf_pre_emphasis_cmp, key=lambda x: x[3])
    for (unit, nps_port, lane_cnt, property_data) in ordered_key_list:
        cmd_str = 'npx_diag phy show pre-emphasis unit={0} portlist={1}' \
                  ' lane-cnt={2} property={3}'.format(unit, nps_port, lane_cnt, property_data) + '\n'
        popen_obj.stdin.write(cmd_str)
        exec_cmd.append(cmd_str)
        time.sleep(0.005)

    return exec_cmd


@decro_timeit
def get_port_running_config_mdio_exec_cmd(popen_obj, user_port_list):
    exec_cmd = []

    # show mdio
    portlist_key_ol = sorted(list(user_port_list))
    for port_name in portlist_key_ol:
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V_NPS_PORT
        unit, port = user_port_list[port_name][k]
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V_MDIO
        mdio_config_ol = sorted(list(user_port_list[port_name][k]))
        for devad, addr in mdio_config_ol:
            cmd_str = 'npx_diag phy show mdio unit={0} portlist={1}' \
                      ' devad={2} addr={3}'.format(unit, port, devad, addr) + '\n'
            popen_obj.stdin.write(cmd_str)
            exec_cmd.append(cmd_str)
            time.sleep(0.005)

    return exec_cmd


@decro_timeit
@decro_get_docker_exec
def get_port_running_config_check_output(popen_obj, pre_emphasis_config, user_port_list):
    return get_port_running_config_exec_cmd(popen_obj, pre_emphasis_config, user_port_list)


@decro_timeit
@decro_get_docker_exec
def get_port_running_config_mdio_check_output(popen_obj, user_port_list):
    return get_port_running_config_mdio_exec_cmd(popen_obj, user_port_list)


@decro_timeit
def get_port_running_config(show_cmd_buf, pre_emphasis_config, user_port_list):
    # get media
    # port speed medium admin an  eee fec flow-ctrl status loopback cut-through
    # ---- ----- ------ ----- --- --- --- --------- ------ -------- -----------
    # 0    100g  sr4    en    dis dis dis dis       down   dis      dis
    running_media = dict()
    portlist = []
    for port_name in user_port_list:
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V_NPS_PORT
        portlist.append(user_port_list[port_name][k][1])
    pt_str = r'''^\s*
             (?P<port>{})\s+  #interface
             (?P<speed>[^\s]+)\s+  #speed
             (?P<media>\w+)\s+  #media
             (?P<admin>\w+)\s+  #admin
             .*$
             '''
    pt_str = pt_str.format('|'.join(portlist))
    pt = re.compile(pt_str, re.I | re.M | re.X)
    result = pt.finditer(show_cmd_buf)
    for r in result:
        k = ('0', r.group('port'))
        running_media[k] = r.group('media')

    # get pre-emphasis
    # npx_diag phy show pre-emphasis unit={0} portlist={1}
    #  lane-cnt={2} property={3}'
    running_pre_emphasis = dict()
    ordered_key_list = sorted(list(pre_emphasis_config), cmp=my_udf_pre_emphasis_cmp, key=lambda x: x[3])
    pt = re.compile(r'^.*\s+data\s*=\s*(?P<data>[\w.]+).*$', re.I | re.M)
    running_pre_emphasis_ol = pt.findall(show_cmd_buf)
    for i in range(0, len(running_pre_emphasis_ol)):
        hl = [hex(y)[2:] for y in [int(x, 16) for x in running_pre_emphasis_ol[i].split('.')]]
        uniform_data = '0x' + '.'.join(hl)
        k = ordered_key_list[i]
        running_pre_emphasis[k] = uniform_data

    return running_media, running_pre_emphasis


@decro_timeit
def get_port_running_config_mdio(show_cmd_buf, user_port_list):
    # get mdio
    # admin@switch:~$ npx_diag phy show mdio unit=0 portlist=0 devad=0x1E addr=0x2
    # port 000: data=0x0000
    running_mdio = dict()

    pt = re.compile(r'^.*\s+data\s*=\s*(?P<data>[\w.]+).*$', re.I | re.M)
    portlist_key_ol = sorted(list(user_port_list))
    rst_mdio_ol = pt.findall(show_cmd_buf)
    for i in range(0, len(rst_mdio_ol)):
        hl = [hex(y)[2:] for y in [int(x, 16) for x in rst_mdio_ol[i].split('.')]]
        uniform_data = '0x' + '.'.join(hl)
        port_name = portlist_key_ol[i]
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V_NPS_PORT
        unit, port = user_port_list[port_name][k]
        k = KEY_PHY_PORT_INFO_V_USER_PORT_V_MDIO
        mdio_config_ol = sorted(list(user_port_list[port_name][k]))
        k = (unit, port)
        for devad, addr in mdio_config_ol:
            if k in running_mdio:
                running_mdio[k].update({(devad, addr): uniform_data})
            else:
                running_mdio[k] = {(devad, addr): uniform_data}

    return running_mdio


def cmp_running_media_pre_emphasis(running_media,
                                   media_config,
                                   running_mdio,
                                   mdio_config,
                                   running_pre_emphasis,
                                   pre_emphasis_config):
    media_changed = 0
    if operator.ne(running_media, media_config):
        media_changed = 1

    mdio_changed = 0
    if operator.ne(running_mdio, mdio_config):
        mdio_changed = 1

    pre_emphasis_changed = 0
    if operator.ne(running_pre_emphasis, pre_emphasis_config):
        pre_emphasis_changed = 1

    return media_changed, mdio_changed, pre_emphasis_changed


@decro_timeit
def check_port_running_config(
        media_config,
        mdio_config,
        pre_emphasis_config,
        user_port_list):

    err_ret = (-1, 0, 0, 0)

    ret, exec_cmd, output = get_port_running_config_check_output(pre_emphasis_config, user_port_list)
    if 0 != ret:
        return err_ret
    running_media, running_pre_emphasis = \
        get_port_running_config(output, pre_emphasis_config, user_port_list)

    ret, exec_cmd, output = get_port_running_config_mdio_check_output(user_port_list)
    if 0 != ret:
        return err_ret
    running_mdio = \
        get_port_running_config_mdio(output, user_port_list)

    if len(running_media) != len(media_config) \
            or len(running_mdio) != len(mdio_config) \
            or len(running_pre_emphasis) != len(pre_emphasis_config):
        return err_ret

    media_changed, mdio_changed, pre_emphasis_changed = \
        cmp_running_media_pre_emphasis(running_media,
                                       media_config,
                                       running_mdio,
                                       mdio_config,
                                       running_pre_emphasis,
                                       pre_emphasis_config)

    return ret, media_changed, mdio_changed, pre_emphasis_changed


@decro_timeit
def set_port_running_media_pre_emphasis_exec_cmd(
        popen_obj,
        media_changed,
        media_config,
        pre_emphasis_changed,
        pre_emphasis_config,
        user_port_list):

    cmd_change = []

    if 0 != media_changed:
        for (unit, nps_port), media in media_config.items():
            # npx_diag port set property unit=0 portlist=26 medium-type=cr4
            cmd_str = 'npx_diag port set property unit={0} portlist={1} medium-type={2}'.format(
                unit, nps_port, media)
            popen_obj.stdin.write(cmd_str + '\n')
            time.sleep(0.005)
            cmd_change.append(cmd_str)

    if 0 != pre_emphasis_changed:
        ordered_key_list = sorted(list(pre_emphasis_config), cmp=my_udf_pre_emphasis_cmp, key=lambda x: x[3])
        for (unit, nps_port, lane_cnt, property_data) in ordered_key_list:
            data = pre_emphasis_config[(unit, nps_port, lane_cnt, property_data)]
            cmd_str = 'npx_diag phy set pre-emphasis unit={0} portlist={1} lane-cnt={2} ' \
                      'property={3} data={4}'.format(unit, nps_port, lane_cnt, property_data, data)
            popen_obj.stdin.write(cmd_str + '\n')
            time.sleep(0.005)
            cmd_change.append(cmd_str)

    get_port_running_config_exec_cmd(popen_obj, pre_emphasis_config, user_port_list)

    return cmd_change


@decro_timeit
def set_port_running_mdio_exec_cmd(
        popen_obj,
        mdio_changed,
        mdio_config,
        user_port_list):

    cmd_change = []

    if 0 != mdio_changed:
        for (unit, nps_port), mdio_values in mdio_config.items():
            # npx_diag phy show mdio portlist=0 devad=0x1E addr=0x2 data=0x8000
            for (devad, addr), v in mdio_values.items():
                cmd_str = 'npx_diag phy set mdio unit={0} portlist={1} devad={2} addr={3} data={4}'.format(
                    unit, nps_port, devad, addr, v)
                popen_obj.stdin.write(cmd_str + '\n')
                time.sleep(0.005)
                cmd_change.append(cmd_str)

    get_port_running_config_mdio_exec_cmd(popen_obj, user_port_list)

    return cmd_change


@decro_timeit
@decro_get_docker_exec
def set_port_running_config_check_output(
        popen_obj,
        media_changed,
        media_config,
        pre_emphasis_changed,
        pre_emphasis_config,
        user_port_list):
    # set pre-emphasis in chip
    exec_cmd = set_port_running_media_pre_emphasis_exec_cmd(popen_obj,
                                                            media_changed,
                                                            media_config,
                                                            pre_emphasis_changed,
                                                            pre_emphasis_config,
                                                            user_port_list)

    return exec_cmd


@decro_timeit
@decro_get_docker_exec
def set_port_running_config_mdio_check_output(
        popen_obj,
        mdio_changed,
        mdio_config,
        user_port_list):
    # set pre-emphasis in chip
    exec_cmd = set_port_running_mdio_exec_cmd(popen_obj, mdio_changed, mdio_config, user_port_list)

    return exec_cmd


@decro_timeit
def set_port_running_config_hw(media_changed,
                               media_config,
                               mdio_changed,
                               mdio_config,
                               pre_emphasis_changed,
                               pre_emphasis_config,
                               user_port_list):
    err_ret = (-1, 1, {}, 1, {}, 1, {})

    # exec media and pre-emphasis config cmd
    ret, cmd_change_media_pre_emphasis, output = set_port_running_config_check_output(media_changed,
                                                                                      media_config,
                                                                                      pre_emphasis_changed,
                                                                                      pre_emphasis_config,
                                                                                      user_port_list)
    if 0 != ret:
        return err_ret
    running_media, running_pre_emphasis = get_port_running_config(output, pre_emphasis_config, user_port_list)

    # exec mdio cmd
    ret, cmd_change_mdio, output = set_port_running_config_mdio_check_output(mdio_changed, mdio_config, user_port_list)
    if 0 != ret:
        return err_ret
    running_mdio = get_port_running_config_mdio(output, user_port_list)

    check_media_changed, check_mdio_changed, check_pre_emphasis_changed = \
        cmp_running_media_pre_emphasis(running_media,
                                       media_config,
                                       running_mdio,
                                       mdio_config,
                                       running_pre_emphasis,
                                       pre_emphasis_config)
    cmd_change = cmd_change_media_pre_emphasis + cmd_change_mdio
    ret = (0, cmd_change, check_media_changed, running_media, check_mdio_changed, running_mdio,
           check_pre_emphasis_changed, running_pre_emphasis)
    return ret


@decro_timeit
def set_port_running_config(media_changed,
                            media_config,
                            mdio_changed,
                            mdio_config,
                            pre_emphasis_changed,
                            pre_emphasis_config,
                            user_port_list):
    worker_id = threading.current_thread().name

    ret = set_port_running_config_hw(media_changed,
                                     media_config,
                                     mdio_changed,
                                     mdio_config,
                                     pre_emphasis_changed,
                                     pre_emphasis_config,
                                     user_port_list)
    if 0 != ret[0]:
        return -1, []
    cmd_change = ret[1]
    check_media_changed = ret[2]
    running_media = ret[3]
    running_mdio = ret[5]
    check_pre_emphasis_changed = ret[6]
    running_pre_emphasis = ret[7]
    if check_media_changed:
        g_sfp_logger.error("worker {} change port {} media from {} to {} failed\n".format(
            worker_id, user_port_list, running_media, media_config))

        ret = -2
        cmd_change = []
        # cr is not supported in sdk 2.0.4 and all previous version, kr is suggested by sdk rd
        retry = False
        for (unit, nps_port), media in media_config.items():
            if media == 'cr':
                media_config[(unit, nps_port)] = 'sr'
                retry = True
        if retry:
            ret = set_port_running_config_hw(media_changed,
                                             media_config,
                                             mdio_changed,
                                             mdio_config,
                                             pre_emphasis_changed,
                                             pre_emphasis_config,
                                             user_port_list)
            if 0 != ret[0]:
                return -1, []
            cmd_change = ret[1]
            check_media_changed = ret[2]
            check_mdio_changed = ret[4]
            check_pre_emphasis_changed = ret[6]
            if 0 != ret or check_media_changed or check_pre_emphasis_changed:
                return -2, []

    if check_pre_emphasis_changed:
        g_sfp_logger.error("worker {} change port {} pre-emphasis from {} to {} failed\n".format(
            worker_id, user_port_list, running_pre_emphasis, pre_emphasis_config))
        return -3, []

    if media_changed:
        g_sfp_logger.critical("worker {} change port {} media from {} to {} succeed\n".format(
            worker_id, user_port_list, running_media, media_config))

    if mdio_changed:
        g_sfp_logger.critical("worker {} change port {} mdio from {} to {} succeed\n".format(
            worker_id, user_port_list, running_mdio, mdio_config))

    if pre_emphasis_changed:
        g_sfp_logger.error("worker {} change port {} pre-emphasis from {} to {} succeed\n".format(
            worker_id, user_port_list, running_pre_emphasis, pre_emphasis_config))

    return 0, cmd_change


def get_default_pre_emphasis_config_key(phy_port_info, sfp_info):
    user_port_list = get_phy_user_port_list(phy_port_info)
    if 'DAC' == get_sfp_type(sfp_info):
        default_config_file = DEFAULT_PRE_EMPHASIS_DAC_CFG_FILE_NAME
        media_type = 'DAC'
    else:
        default_config_file = DEFAULT_PRE_EMPHASIS_OPT_CFG_FILE_NAME
        media_type = 'OPT'

    g_sfp_logger.info(
        "worker {} port {} use default {} pre-emphasis config \n".format(
            threading.current_thread().name,
            user_port_list, media_type))
    split_list = os.path.splitext(default_config_file)[0].split('_')

    return split_list[0], split_list[1]


def get_phy_port_sfp_specific_pre_emphasis(phy_port_info, sfp_info):
    """
    get pre-emphasis config of phy port with specific sfp type from configuration database
    :param phy_port_info: phy port number
    :param sfp_info: sfp info dict
    :return:
    """
    ret = 0
    pre_emphasis_config = dict()

    if len(phy_port_info) == 0:
        return -1, pre_emphasis_config

    # get pre-emphasis config
    k = KEY_PHY_PORT_INFO_V_PRE_EMPHASIS
    if k not in phy_port_info:
        return -2, pre_emphasis_config
    sfp_pre_emphasis_value = phy_port_info[k]
    key_sfp_pre_emphasis = KEY_PHY_PORT_INFO_V_PRE_EMPHASIS_V(sfp_info)
    if key_sfp_pre_emphasis not in sfp_pre_emphasis_value:
        key_sfp_pre_emphasis = get_default_pre_emphasis_config_key(phy_port_info, sfp_info)
    else:
        user_port_list = get_phy_user_port_list(phy_port_info)
        g_sfp_logger.info(
            "worker {}: port {} use {} specific pre-emphasis config \n".format(
                threading.current_thread().name,
                user_port_list,
                key_sfp_pre_emphasis))
    pre_emphasis_config = sfp_pre_emphasis_value[key_sfp_pre_emphasis]

    return ret, pre_emphasis_config


def update_phy_port_sfp_info(phy_port_info, sfp_info):
    if len(phy_port_info) > 0:
        phy_port_info[KEY_PHY_PORT_INFO_V_PRESENT_SFP_INFO] = sfp_info


@decro_timeit
def update_phy_port_running_config(phy_port_info, sfp_info):
    """
    update media and pre-emphasis config of phy port according to sfp_info
    :param phy_port_info:
    :param sfp_info:
    :return:
    """
    worker_id = threading.current_thread().name
    user_port_list = get_phy_user_port_list(phy_port_info)

    # get phy port media config
    sfp_specific_media_config = get_phy_port_sfp_specific_media(user_port_list)

    # get phy port mdio config
    sfp_specific_mdio_config = get_phy_port_sfp_specific_mdio(user_port_list)

    # get phy port sfp specific pre-emphasis config
    ret, sfp_specific_pre_emphasis_config = get_phy_port_sfp_specific_pre_emphasis(phy_port_info, sfp_info)
    if 0 != ret:
        g_sfp_logger.error("worker {} port {} get_phy_port_sfp_specific_pre_emphasis ret = {}\n".format(
            worker_id, user_port_list, ret))
        return -10 + ret, []

    # check if running media and pre-emphasis in chip is need to set
    ret, media_changed, mdio_changed, pre_emphasis_changed = check_port_running_config(
        sfp_specific_media_config, sfp_specific_mdio_config, sfp_specific_pre_emphasis_config, user_port_list)
    if 0 != ret:
        g_sfp_logger.error("worker {} port {} check_port_running_config ret = {}\n".format(
            worker_id, user_port_list, ret))
        return -20 + ret, []

    # running config in chip is correct,
    if (media_changed == 0) and (mdio_changed == 0) and (pre_emphasis_changed == 0):
        g_sfp_logger.critical('worker {} port {} are correctly set already'
                              ' media:{} mdio: {} pre-emphasis:{}\n'.format(worker_id,
                                                                            user_port_list,
                                                                            sfp_specific_media_config,
                                                                            sfp_specific_mdio_config,
                                                                            sfp_specific_pre_emphasis_config))

        update_phy_port_sfp_info(phy_port_info, sfp_info)
        return 0, []

    # get and save user port admin status
    ret, user_port_admin_status = get_phy_port_admin_status(user_port_list)
    if 0 != ret:
        g_sfp_logger.error("worker {} get port {} admin status failed! ret = {}\n".format(
            worker_id, user_port_list, ret))
        return -30 + ret, []

    # shutdown user ports
    ret = admin_down_user_ports(user_port_admin_status, user_port_list)
    if 0 != ret:
        g_sfp_logger.error("worker {} shutdown {} failed! ret = {}\n".format(worker_id, user_port_list, ret))
        return -40 + ret, []

    # set port media of phy port
    ret, cmd_change = set_port_running_config(media_changed,
                                              sfp_specific_media_config,
                                              mdio_changed,
                                              sfp_specific_mdio_config,
                                              pre_emphasis_changed,
                                              sfp_specific_pre_emphasis_config,
                                              user_port_list)

    if 0 == ret:
        update_phy_port_sfp_info(phy_port_info, sfp_info)
    else:
        ret += -50

    # recover admin status of logical ports
    ret_recover = admin_up_user_ports(user_port_admin_status)
    if 0 != ret_recover:
        g_sfp_logger.error("worker {} restore {} admin status ret = {}\n".format(worker_id, user_port_list, ret))
        # just log

    return ret, cmd_change


@decro_timeit
def is_sys_running():
    """
    check if swss docker is running
    :return: True for running, false for not running
    """
    is_running = False

    # check container swss's run status
    cmd = ['docker', 'ps']
    cmd_out = subprocess.check_output(cmd)
    pt = re.compile(r'^.*\s*swss\s*', re.I | re.M)
    result = pt.search(cmd_out)
    if result is None:
        g_sfp_logger.error("cmd={} fail: type cmd_out {}, cmd_out:{}\n".format(cmd, type(cmd_out), cmd_out))
        return is_running

    # check redis database to confirm it's running status
    pcmd = subprocess.Popen(['redis-cli'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cmd_input = 'select 1\nHLEN HIDDEN\n'
    cmd_out = pcmd.communicate(cmd_input)
    if cmd_out[1] != '':
        # cmd exec fail
        g_sfp_logger.error("cmd={} fail: type cmd_out {}, cmd_out:{}\n".format(cmd, type(cmd_out), cmd_out))
        return is_running
    pt = re.compile(r'OK.*(\d+).*', re.I | re.S)
    result = pt.search(cmd_out[0])
    if result is None:
        g_sfp_logger.error("cmd={} match fail: cmd_out:{}\n".format(cmd, cmd_out[0]))

    # check if interface is initialized
    cmd = ['show', 'interface', 'status']
    pcmd = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cmd_out = pcmd.communicate()
    if cmd_out[1] != '':
        # cmd exec fail
        g_sfp_logger.error("cmd={} type cmd_out {}, cmd_out:{}\n".format(cmd, type(cmd_out), cmd_out))
        return is_running

    # Interface    Lanes    Speed    MTU         Alias    Oper    Admin
    # -----------  -------  -------  -----  ------------  ------  -------
    # Ethernet12       20      10G   9100  Ethernet13/1      up       up
    pt_str = r'''^\s*
                 (?P<port_name>\w+)\s+  #interface
                 (?P<lanes>[\d,]+)\s+  #lanes
                 [\w/]+\s+  #speed
                 \d+\s+  #mtu
                 (?P<alias>[\w/]+)\s+
                 (up|down)\s+
                 (?P<admin>\w+)\s*
                 .*$
                 '''
    pt = re.compile(pt_str, re.I | re.M | re.X)
    result = pt.search(cmd_out[0])
    if result is None:
        g_sfp_logger.error("cmd={} type cmd_out {}, cmd_out:{}\n".format(cmd, type(cmd_out), cmd_out))
        return is_running

    return True


@decro_timeit
def sfp_monitor_by_port(phy_port, phy_port_info):
    worker_id = threading.current_thread().name

    if len(phy_port_info) == 0:
        g_sfp_logger.error("worker_id {} phy_port info {} is not initialized\n".format(worker_id, phy_port))
        return -1, []

    if KEY_PHY_PORT_INFO_V_USER_PORT in phy_port_info:
        user_port_list = get_phy_user_port_list(phy_port_info)
    else:
        g_sfp_logger.error("worker_id {} phy_port info {} has no user ports\n".format(worker_id, phy_port))
        return -2, []

    # check sfp present status and sfp eeprom info of phy port
    present = get_port_sfp_present_status(int(phy_port))
    if not present:
        return 0, []
    sfp_info = get_port_sfp_info(int(phy_port))

    # check sfp info change of phy port
    changed = check_sfp_info_change(phy_port_info, sfp_info)
    if not changed:
        return 0, []

    g_sfp_logger.critical("worker_id {} port={}: {} sfp info changed to {}\n".format(
        worker_id, phy_port, user_port_list, sfp_info))

    # if sfp changed then init port media config
    p_ret = init_phy_port_media_mdio_config(phy_port_info, sfp_info)
    if 0 != p_ret:
        g_sfp_logger.error(
            "worker_id {} init_phy_port_media_mdio_config fail, port={}: {} ret={}\n".format(
                worker_id, phy_port, user_port_list, p_ret))
        return -3, []

    # set media and pre-emphasis of port
    ret, cmd_change = update_phy_port_running_config(phy_port_info, sfp_info)
    if 0 != ret:
        g_sfp_logger.error("worker_id {} update_phy_port_running_config"
                           " fail, port={}: {} ret={}\n".format(worker_id, phy_port, user_port_list, p_ret))
        return -4, []

    return 0, cmd_change


def sfp_monitor_by_group(port_list_dict, mask_ports, msg_queue):
    """
    check sfp type and set pre-emphasis of all ports
    :param port_list_dict:
    :param mask_ports:
    :param msg_queue:
    :return:
    """
    ret = 0
    global _g_process_exit

    worker_id = threading.current_thread().name
    all_changed_cmd = []
    for phy_port in port_list_dict:
        # exit as soon as possible
        if _g_process_exit:
            break

        # skip user masked port
        skip = int(phy_port) in mask_ports or str(phy_port) in mask_ports
        if skip:
            continue

        # get user port of phy port
        phy_port_info = get_phy_port_info(port_list_dict, phy_port)
        ret, port_changed_cmd = sfp_monitor_by_port(phy_port, phy_port_info)
        if 0 == ret:
            all_changed_cmd += port_changed_cmd

    # send sfp change cmd to auto save dynamic pre-emphasis config
    if (msg_queue is not None) and (len(all_changed_cmd) != 0):
        msg_queue.put(all_changed_cmd)
        g_sfp_logger.info('worker_id {} change pre-emphasis:\n{}\n'.format(worker_id, all_changed_cmd))

    return ret


def single_thread_do_task(period, port_list_dict, service_mode, mask_port_list, msg_queue):
    """
    main port sfp monitor function
    :param period:
    :param port_list_dict:
    :param service_mode:
    :param mask_port_list:
    :param msg_queue:
    :return:
    """
    global _g_process_exit
    global g_sfp_logger

    worker_id = threading.current_thread().name

    # auto save or log port dynamic pre-emphasis config
    auto_save = get_global_running_config(KEY_MONITOR_USER_CFG_AUTO_SAVE)
    while not _g_process_exit:
        ret = sfp_monitor_by_group(port_list_dict, mask_port_list, msg_queue)
        if 0 != ret:
            g_sfp_logger.error("worker:{} monitor {} sfp_monitor_by_group ret ={}\n".format(
                worker_id, port_list_dict.keys(), ret))

        # update port_config.nps
        if auto_save:
            auto_save_startup_config(msg_queue)

        if 0 == service_mode:
            break

        # exit as soon as possible
        if not _g_process_exit:
            time.sleep(period)

    g_sfp_logger.critical("worker:{} exit\n".format(worker_id))

    return


def worker_do_task(period, port_list_dict, service_mode, mask_port_list, msg_queue):
    """
    main port sfp monitor function
    :param period:
    :param port_list_dict:
    :param service_mode:
    :param mask_port_list:
    :param msg_queue:
    :return:
    """
    global _g_process_exit
    global g_sfp_logger

    worker_id = threading.current_thread().name
    while not _g_process_exit:
        ret = sfp_monitor_by_group(port_list_dict, mask_port_list, msg_queue)
        if 0 != ret:
            g_sfp_logger.error("worker:{} monitor {} sfp_monitor_by_group ret ={}\n".format(
                worker_id, port_list_dict.keys(), ret))

        if 0 == service_mode:
            break

        # exit as soon as possible
        if not _g_process_exit:
            time.sleep(period)

    g_sfp_logger.critical("worker:{} exit\n".format(worker_id))

    return


def sig_handler(sig, frame):
    global _g_process_exit

    _g_process_exit = True
    if not DEBUG_MODE:
        g_sfp_logger.critical('receive a signal {} {}, exit.\n'.format(sig, frame.f_code.co_name))
    else:
        print('receive a signal {} {}, exit.\n'.format(sig, frame.f_code.co_name))


def slice_dict(u_dict, start, end, step):
    sliced_dict = dict()

    keys_list = u_dict.keys()[start:end:step]
    for k in keys_list:
        sliced_dict[k] = u_dict[k]

    return sliced_dict


def get_pre_emphasis_change_cmd(cmd_queue):
    """
    get all change cmd from msg queue with none block method
    :param cmd_queue:
    :return:
    """
    all_change_cmd = []

    if cmd_queue is None:
        return all_change_cmd

    # do not block!
    while not cmd_queue.empty():
        try:
            change_cmd = cmd_queue.get(False)
            all_change_cmd += change_cmd
        except queue.Empty:
            pass
    all_change_cmd = [cmd[len('npx_diag '):] for cmd in all_change_cmd]
    return all_change_cmd


def partion_start_up_config(nps_cfg_full_path):
    worker_id = threading.current_thread()

    # split content of port_cfg.nps into n partions
    pat_str = r'''^\s*port\s+set\s+property\s+     #property
            ([\w]+\s*=\s*(?P<unit>\d+)\s+){0,1}   #unit=0 
            [\w]+\s*=\s*(?P<portlist>[\d\-]+)\s+  #portlist=0
            medium-type\s*=\s*(?P<media>\w+)  #media-type=sr
            .*$
            '''
    pat_pre_media = re.compile(pat_str, re.M | re.I | re.X)

    pat_str = r'''^\s*phy\s+set\s+mdio\s+     #phy set mdio
            ([\w]+\s*=\s*(?P<unit>\d+)\s+){0,1}   #unit=0 
            [\w]+\s*=\s*(?P<portlist>[\d\-]+)\s+  #portlist=0
            [\w\-]+\s*=\s*(?P<devad>\w+)\s+ #devad
            [\w]+\s*=\s*(?P<addr>\w+)\s+    #addr
            .*$
            '''
    pat_pre_mdio = re.compile(pat_str, re.M | re.I | re.X)

    pat_str = r'''^\s*phy\s+set\s+pre-emphasis\s+     #phy set pre-emphasis
            ([\w]+\s*=\s*(?P<unit>\d+)\s+){0,1}   #unit=0 
            [\w]+\s*=\s*(?P<portlist>[\d\-]+)\s+  #portlist=0
            [\w\-]+\s*=\s*(?P<lane_cnt>\d+)\s+ #lane-cnt=4
            [\w]+\s*=\s*(?P<property>\w+)\s+    #property=cn1
            .*$
            '''
    pat_pre_emphasis = re.compile(pat_str, re.M | re.I | re.X)

    block_reg_dict = {'media': pat_pre_media, 'mdio': pat_pre_mdio, 'emphasis': pat_pre_emphasis}
    block_index = {}

    cfg_file_block_buf = []
    with open(nps_cfg_full_path, mode='r') as nps_cfg_fp:
        lines_buf = nps_cfg_fp.readlines()
        cur_block_index = -1
        last_block_type = 'NULL'
        for line in lines_buf:
            if line.strip() == '' and last_block_type != 'NULL':
                'keep blank lines'
                cur_block_type = last_block_type
            else:
                cur_block_type = 'other'
                for k in block_reg_dict:
                    result = block_reg_dict[k].search(line)
                    if result is not None:
                        cur_block_type = k
                        break

            if (cur_block_type != last_block_type) and \
                    ((cur_block_type not in block_reg_dict) or (cur_block_type not in block_index)):
                    cur_block_index += 1
                    block_index[cur_block_type] = cur_block_index
                    cfg_file_block_buf.append(line)
            else:
                dst_index = block_index[cur_block_type]
                cfg_file_block_buf[dst_index] += line

            last_block_type = cur_block_type

        for i in range(0, len(cfg_file_block_buf)):
            g_sfp_logger.debug('worker {} split {} to {} parts part {} = {}\n'.format(
                worker_id, nps_cfg_full_path, len(cfg_file_block_buf), i, cfg_file_block_buf[i]))

    return cfg_file_block_buf, block_index


def update_media_cmd_of_startup_cfg(startup_cfg_buf, block_index, change_cmd_buf):
    worker_id = threading.current_thread()

    pat_str = r'''^\s*port\s+set\s+property\s+   
            (unit\s*=\s*(?P<unit>\d+)\s+){0,1}   #unit=0 
            [\w]+\s*=\s*(?P<portlist>[\d\-]+)\s+  #portlist=0 
            medium-type\s*=\s*(?P<media>\w+)  #media-type=sr 
            .*$ 
            '''
    pat = re.compile(pat_str, re.M | re.I | re.X)
    for cmd in change_cmd_buf:
        result = pat.search(cmd)
        if result is None:
            continue
        unit = result.group('unit')
        if unit is None:
            unit = 0
        nps_port = result.group('portlist')
        change_cmd_pat_str = r'''^\s*port\s+set\s+property\s+      
                        (unit\s*=\s*{}\s+){}   #unit=0  
                        portlist\s*=\s*{}\s+  #portlist=0 
                        .*$ 
                        '''
        change_cmd_pat_str = change_cmd_pat_str.format(unit, '{0,1}', nps_port)
        change_cmd_buf_pat = re.compile(change_cmd_pat_str, re.M | re.I | re.X)
        startup_cfg_buf[block_index], sub_cnt = change_cmd_buf_pat.subn(cmd, startup_cfg_buf[block_index])
        if sub_cnt == 0:
            startup_cfg_buf[block_index] += cmd + '\n'
            g_sfp_logger.debug('worker {} new cmd {} add in buffer\n'.format(worker_id, cmd))
        else:
            g_sfp_logger.debug('worker {} cmd {} updated in buffer\n'.format(worker_id, cmd))


def update_mdio_cmd_of_startup_cfg(startup_cfg_buf, block_index, change_cmd_buf):
    worker_id = threading.current_thread()

    pat_str = r'''^phy\s+set\s+mdio\s+     #phy set mdio 
            (unit\s*=\s*(?P<unit>\d+)\s+){0,1}   #unit=0  
            portlist\s*=\s*(?P<portlist>[\d\-]+)\s+  #portlist=0 
            devad\s*=\s*(?P<devad>\w+)\s+ #devad 
            addr\s*=\s*(?P<addr>\w+)\s+    #addr 
            .*$ 
            '''
    pat = re.compile(pat_str, re.M | re.I | re.X)
    for cmd in change_cmd_buf:
        result = pat.search(cmd)
        if result is None:
            continue
        unit = result.group('unit')
        if unit is None:
            unit = 0
        nps_port = result.group('portlist')
        devad = result.group('devad')
        addr = result.group('addr')

        change_cmd_pat_str = r'''^phy\s+set\s+mdio\s+     #phy set mdio 
                        (unit\s*=\s*{}\s+){}   #unit=0  
                        portlist\s*=\s*{}\s+  #portlist=0 
                        devad\s*=\s*{}\s+     #devad 
                        addr\s*=\s*{}\s+    #addr 
                        .*$ 
                        '''
        change_cmd_pat_str = change_cmd_pat_str.format(unit, '{0,1}', nps_port, devad, addr)
        change_cmd_buf_pat = re.compile(change_cmd_pat_str, re.M | re.I | re.X)
        startup_cfg_buf[block_index], sub_cnt = change_cmd_buf_pat.subn(cmd, startup_cfg_buf[block_index])
        if sub_cnt == 0:
            startup_cfg_buf[block_index] += cmd + '\n'
            g_sfp_logger.debug('worker {} new cmd {} add in buffer\n'.format(worker_id, cmd))
        else:
            g_sfp_logger.debug('worker {} cmd {} updated in buffer\n'.format(worker_id, cmd))


def update_pre_emphasis_cmd_of_startup_cfg(startup_cfg_buf, block_index, change_cmd_buf):
    worker_id = threading.current_thread()

    pat_str = r'''^phy\s+set\s+pre-emphasis\s+     #phy set pre-emphasis 
            (unit\s*=\s*(?P<unit>\d+)\s+){0,1}   #unit=0  
            portlist\s*=\s*(?P<portlist>[\d\-]+)\s+  #portlist=0 
            lane-cnt\s*=\s*(?P<lane_cnt>\d+)\s+ #lane-cnt=4 
            property\s*=\s*(?P<property>\w+)\s+    #property=cn1 
            .*$ 
            '''
    pat = re.compile(pat_str, re.M | re.I | re.X)
    for cmd in change_cmd_buf:
        result = pat.search(cmd)
        if result is None:
            continue
        unit = result.group('unit')
        if unit is None:
            unit = 0
        nps_port = result.group('portlist')
        lane_cnt = result.group('lane_cnt')
        property_data = result.group('property')

        change_cmd_pat_str = r'''^phy\s+set\s+pre-emphasis\s+     #phy set pre-emphasis 
                        (unit\s*=\s*{}\s+){}   #unit=0  
                        portlist\s*=\s*{}\s+  #portlist=0 
                        lane-cnt\s*=\s*{}\s+ #lane-cnt=4 
                        property\s*=\s*{}\s+    #property=cn1 
                        .*$ 
                        '''
        change_cmd_pat_str = change_cmd_pat_str.format(unit, '{0,1}', nps_port, lane_cnt, property_data)
        change_cmd_buf_pat = re.compile(change_cmd_pat_str, re.M | re.I | re.X)
        startup_cfg_buf[block_index], sub_cnt = change_cmd_buf_pat.subn(cmd, startup_cfg_buf[block_index])
        if sub_cnt == 0:
            startup_cfg_buf[block_index] += cmd + '\n'
            g_sfp_logger.debug('worker {} new cmd {} add in buffer\n'.format(worker_id, cmd))
        else:
            g_sfp_logger.debug('worker {} cmd {} updated in buffer\n'.format(worker_id, cmd))


@decro_timeit
def auto_save_startup_config(cmd_queue):
    """
    auto save change cmd in port_cfg.nps
    :param cmd_queue:
    :return:
    """

    worker_id = threading.current_thread()

    # get all change cmds from msg queue
    change_cmd = get_pre_emphasis_change_cmd(cmd_queue)
    if len(change_cmd) == 0:
        return 0

    platform_path, hwsku_path = _get_path_to_platform_hwsku()
    nps_cfg_full_path = os.path.join(hwsku_path, PORT_CFG_NPS_FILE_NAME)
    nps_cfg_exist = os.path.isfile(nps_cfg_full_path)
    nps_cfg_backup_full_path = nps_cfg_full_path + '.backup'
    backup_exist = os.path.isfile(nps_cfg_backup_full_path)

    # check port_cfg.nps and backup file
    if (nps_cfg_exist, backup_exist) == (True, True):
        # perfect
        g_sfp_logger.debug('worker {} {} and {} are exist.\n'.format(
            worker_id, nps_cfg_full_path, nps_cfg_backup_full_path))
    elif (nps_cfg_exist, backup_exist) == (True, False):
        # backup port_config.nps
        shutil.copy(nps_cfg_full_path, nps_cfg_backup_full_path)
        g_sfp_logger.critical('worker {} backup {} to {}\n'.format(
            worker_id, nps_cfg_full_path, nps_cfg_backup_full_path))
    elif (nps_cfg_exist, backup_exist) == (False, True):
        # restore port_config.nps from backup file
        shutil.copy(nps_cfg_backup_full_path, nps_cfg_full_path)
        g_sfp_logger.warning('worker {} {} is restored from {}\n'.format(
            worker_id, nps_cfg_full_path, nps_cfg_backup_full_path))
    elif (nps_cfg_exist, backup_exist) == (False, False):
        # port_config.nps and backup are lost
        g_sfp_logger.error('worker {} {} is lost\n'.format(worker_id, nps_cfg_full_path))
        return -1

    # update cmd in cfg file buf
    cfg_file_block_buf, block_index = partion_start_up_config(nps_cfg_full_path)
    if 'media' not in block_index:
        media_block_index = len(cfg_file_block_buf) - 1
    else:
        media_block_index = block_index['media']
    update_media_cmd_of_startup_cfg(cfg_file_block_buf, media_block_index, change_cmd)

    if 'mdio' not in block_index:
        mdio_block_index = len(cfg_file_block_buf) - 1
    else:
        mdio_block_index = block_index['mdio']
    update_mdio_cmd_of_startup_cfg(cfg_file_block_buf, mdio_block_index, change_cmd)

    if 'emphasis' not in block_index:
        pre_emphasis_block_index = len(cfg_file_block_buf) - 1
    else:
        pre_emphasis_block_index = block_index['emphasis']
    update_pre_emphasis_cmd_of_startup_cfg(cfg_file_block_buf, pre_emphasis_block_index, change_cmd)

    # write new config to port_cfg.nps
    nps_cfg_tmp_full_path = nps_cfg_full_path + '.tmp'
    updated_cfg_content = ''
    for buf_block in cfg_file_block_buf:
        updated_cfg_content += buf_block

    with open(nps_cfg_tmp_full_path, mode='w') as nps_cfg_tmp_fp:
        nps_cfg_tmp_fp.write(updated_cfg_content)
    g_sfp_logger.debug('worker {} write cmd to {}\n'.format(worker_id, nps_cfg_tmp_full_path))

    os.remove(nps_cfg_full_path)
    g_sfp_logger.debug('worker {} remove {}\n'.format(worker_id, nps_cfg_full_path))

    os.rename(nps_cfg_tmp_full_path, nps_cfg_full_path)
    g_sfp_logger.debug('worker {} rename {} to {}\n'.format(worker_id, nps_cfg_tmp_full_path, nps_cfg_full_path))

    g_sfp_logger.critical('worker {} save cmd to {}\n'.format(worker_id, nps_cfg_full_path))


def main_do_task(worker_pool, msg_queue):
    """
    checking sub threads status in master thread
    :param worker_pool:
    :param msg_queue:
    :return:
    """

    # auto save or log port dynamic pre-emphasis config
    auto_save = get_global_running_config(KEY_MONITOR_USER_CFG_AUTO_SAVE)

    while 1:
        # check if all of work threads are exit
        is_alive = False
        for worker in worker_pool:
            is_alive = is_alive or worker.isAlive()
            if is_alive:
                break

        # update port_config.nps
        if auto_save:
            auto_save_startup_config(msg_queue)

        # exit
        if not is_alive:
            return

        time.sleep(1)


def monitor(period, worker_num, service_mode, mask_port_list):
    global g_phy_port_info
    global _g_process_exit

    # register CTRL+C and kill signal
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    # check sys running status
    sys_running = False
    while not sys_running:
        if _g_process_exit:
            return 0
        try:
            sys_running = is_sys_running()
        except Exception as run_error:
            g_sfp_logger.error("sys_running = {} exception:{}\n".format(sys_running, run_error))
        if not sys_running:
            g_sfp_logger.warning("system is not running correctly\n")
            time.sleep(period)

    # initialize global data structure
    initialized = False
    try:
        initialized = init()
    except Exception as run_error:
        g_sfp_logger.error("initialized = {} exception:{}".format(initialized, run_error))
    if 0 != initialized:
        g_sfp_logger.error("global data is not initialized correctly\n")
        return -1

    # 0 means monitor work in single thread mode
    work_pool = []
    q_pre_emphasis_change = queue.Queue()
    if worker_num <= 1:
        single_thread_do_task(period, g_phy_port_info, service_mode, mask_port_list, q_pre_emphasis_change)
    else:
        # create and start monitor worker threads
        phy_port_info_len = len(g_phy_port_info)
        for w in range(1, worker_num + 1):
            phy_port_dict = slice_dict(g_phy_port_info, w, phy_port_info_len, worker_num)
            worker = threading.Thread(target=worker_do_task, args=(period, phy_port_dict, service_mode,
                                                                   mask_port_list, q_pre_emphasis_change))
            g_sfp_logger.debug("name of worker {}:{}\n".format(w, worker.name))
            worker.setDaemon(True)
            work_pool.append(worker)
            worker.start()

        # multi thread exit gracefully
        main_do_task(work_pool, q_pre_emphasis_change)

    return 0


def get_monitor_user_config():
    """
    get monitor user config
    :return:
    """

    # config_list_cond[k]:(valid check func,
    #                      data translate func,
    #                      invalid prompt string)
    config_list_cond = {
        KEY_MONITOR_USER_CFG_PERIOD: (lambda x: type(x) is int and (x > 0),
                                      lambda x: x,
                                      'should be a positive number'),
        KEY_MONITOR_USER_CFG_WORKER_NUMBER: (lambda x: type(x) is int and (x > 0) and (x < 50),
                                             lambda x: x,
                                             'should be a positive 0 - 50 number'),
        KEY_MONITOR_USER_CFG_SERVICE_MODE: (lambda x: type(x) is int,
                                            lambda x: x,
                                            'should be 1 or 0'),
        KEY_MONITOR_USER_CFG_LOGGING_LEVEL: (lambda x: x in get_sfp_logging_level_map(),
                                             lambda x: get_sfp_logging_level_map()[x],
                                             'should be {}'.format(get_sfp_logging_level_map().keys())),
        KEY_MONITOR_USER_CFG_MASK_PORTS: (lambda x: type(x) is list,
                                          lambda x: x,
                                          'should be a port list'),
        KEY_MONITOR_USER_CFG_AUTO_SAVE: (lambda x: type(x) is int,
                                         lambda x: x,
                                         'should be a mumber')
    }

    config_file_path = _get_path_to_monitor_user_config_file()
    if not os.path.isfile(config_file_path):
        # if config file is not exist, return
        return False

    try:
        with open(config_file_path, mode='r') as fp:
            user_config = json.load(fp)

            for cfg_key in user_config:
                data = user_config[cfg_key]
                if cfg_key in config_list_cond:
                    if config_list_cond[cfg_key][0](data):
                        set_global_running_config({cfg_key: config_list_cond[cfg_key][1](data)})
                    else:
                        print("{}:{} {}\n".format(cfg_key, data, config_list_cond[cfg_key][2]))
                else:
                    print("unknown key:{}\n".format(cfg_key))
    except Exception as run_error:
        print('get user config fail, exception={}, use default configuration\n'.format(run_error))

    return True


if __name__ == '__main__':
    os.getpid()

    # init logging
    init_logging()

    # get user running config
    get_monitor_user_config()

    # user may change running config, so get it here
    running_cfg = get_global_running_config()

    # reset logging level
    u_level = running_cfg[KEY_MONITOR_USER_CFG_LOGGING_LEVEL]
    set_sfp_logging_level(u_level)

    # get global running config
    u_period = running_cfg[KEY_MONITOR_USER_CFG_PERIOD]
    u_worker_num = running_cfg[KEY_MONITOR_USER_CFG_WORKER_NUMBER]
    u_service_mode = running_cfg[KEY_MONITOR_USER_CFG_SERVICE_MODE]
    u_mask_port_list = running_cfg[KEY_MONITOR_USER_CFG_MASK_PORTS]
    monitor(u_period, u_worker_num, u_service_mode, u_mask_port_list)
