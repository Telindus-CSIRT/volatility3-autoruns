"""
Volatility 3 Autoruns
Port of tomchop's volatility autoruns plugin for volatility 3
"""

from volatility3.framework import renderers, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist, info, dumpfiles, poolscanner
from volatility3.plugins.windows.registry import hivelist, printkey
import traceback
from datetime import datetime
import logging,re
import xml.etree.ElementTree as ET
import os



EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000

WINLOGON_REGISTRATION_KNOWN_DLLS = [
    'crypt32.dll',
    'cryptnet.dll',
    'cscdll.dll',
    'dimsntfy.dll',
    'sclgntfy.dll',
    'wlnotify.dll',
    'wzcdlg.dll',
]

WINLOGON_COMMON_VALUES = {
    'Userinit': 'userinit.exe',
    'VmApplet': 'rundll32 shell32,Control_RunDLL "sysdm.cpl"',
    'Shell': 'Explorer.exe',
    'TaskMan': "Taskmgr.exe",
    'System': 'lsass.exe',
}

# Service key -> value maps
# Original list from regripper plugins, extra / repeated values from
# http://technet.microsoft.com/en-us/library/cc759275(v=ws.10).aspx
# http://www.atmarkit.co.jp/ait/articles/1705/01/news009_2.html (in Japanese)
# https://github.com/processhacker/processhacker/blob/master/phlib/svcsup.c
# https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/nf-winsvc-createservicea
# https://www.codemachine.com/downloads/win10/winnt.h
SERVICE_TYPES = {
    0x001: "Kernel driver",
    0x002: "File system driver",
    0x004: "Arguments for adapter",
    0x008: "File system driver",
    0x010: "Win32_Own_Process",
    0x020: "Win32_Share_Process",
    0x050: "User_Own_Process TEMPLATE",
    0x060: "User_Share_Process TEMPLATE",
    0x0D0: "User_Own_Process INSTANCE",
    0x0E0: "User_Share_Process INSTANCE",
    0x100: "Interactive",
    0x110: "Interactive",
    0x120: "Share_process Interactive",
    -1: "Unknown",
}

SERVICE_STARTUP = {
    0x00: "Boot Start",
    0x01: "System Start",
    0x02: "Auto Start",
    0x03: "Manual",
    0x04: "Disabled",
    -1: "Unknown",
}

# HKLM\Software\
SOFTWARE_RUN_KEYS = [
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
]

# HKCU\
NTUSER_RUN_KEYS = [
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Run",
    "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
]

# Active Setup only executes commands from the SOFTWARE hive
# See: https://helgeklein.com/blog/2010/04/active-setup-explained/
#      http://blogs.msdn.com/b/aruns_blog/archive/2011/06/20/active-setup-registry-key-what-it-is-and-how-to-create-in-the-package-using-admin-studio-install-shield.aspx
#      http://blog.spiderlabs.com/2014/07/backoff-technical-analysis.html
ACTIVE_SETUP_KEY = "Microsoft\\Active Setup\\Installed Components"

# Abusing MS Fix-It patches to ensure persistence
# References:
# https://www.blackhat.com/docs/asia-14/materials/Erickson/WP-Asia-14-Erickson-Persist-It-Using-And-Abusing-Microsofts-Fix-It-Patches.pdf
# http://blog.cert.societegenerale.com/2015/04/analyzing-gootkits-persistence-mechanism.html
APPCOMPAT_SDB_KEY = "Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB"

# Winlogon Notification packages are supported in pre-Vista versions of Windows only
# See: http://technet.microsoft.com/en-us/library/cc721961(v=ws.10).aspx
WINLOGON_NOTIFICATION_EVENTS = [
    "Lock",
    "Logoff",
    "Logon",
    "Shutdown",
    "StartScreenSaver",
    "StartShell",
    "Startup",
    "StopScreenSaver",
    "Unlock",
]

vollog = logging.getLogger(__name__)

def sanitize_path(path):
    # Clears the path of most equivalent forms
    if path:
        path = path.lower()
        path = path.replace("%systemroot%\\", '')
        path = path.replace("\\systemroot\\", '')
        path = path.replace("%windir%", '')
        path = path.replace("\\??\\", '')
        path = path.replace('\x00', '')
        path = path.replace('"', '').replace("'", '')
        return path

    else:
        return ''

class Autoruns(interfaces.plugins.PluginInterface):
    """Scans for processes that runs at startup"""

    process_dict = {}
    

    _required_framework_version = (2, 0, 0)
    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                        description = 'Memory layer for the kernel',
                                                        architectures = ["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name = "nt_symbols",
                                                    description = "Windows kernel symbols"),
                requirements.BooleanRequirement(name = 'verbose',
                                            description = "Is Verbose",
                                            default = False,
                                            optional = True),
                requirements.ListRequirement(name = 'asep',
                                            element_type = str,
                                            description = "Test string list",
                                            optional = True),
                requirements.PluginRequirement(name = 'pslist',plugin = pslist.PsList,version = (2, 0, 0)),
                requirements.PluginRequirement(name = 'hivelist', plugin = hivelist.HiveList, version = (1, 0, 0)),
                requirements.PluginRequirement(name = 'info', plugin = info.Info, version = (1, 0, 0)),
                requirements.PluginRequirement(name = 'printkey', plugin = printkey.PrintKey, version = (1, 0, 0)),
                requirements.PluginRequirement(name = 'dumpfiles', plugin = dumpfiles.DumpFiles, version = (1, 0, 0)),
                requirements.PluginRequirement(name = 'poolscanner', plugin = poolscanner.PoolScanner, version = (1, 0, 0))
                ]

    def dateString(self,key):
        return datetime.utcfromtimestamp((key.LastWriteTime.QuadPart - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS).isoformat(' ', 'seconds')

    def get_tasks(self):

        vollog.debug('Started get_tasks()')
        tasks = []
        parsed_tasks = []

        try:
            constraints = poolscanner.PoolScanner.builtin_constraints(self.config['nt_symbols'], [b'Fil\xe5', b'File'])
            for file in poolscanner.PoolScanner.generate_pool_scan(context = self.context,layer_name = self.config['primary'], symbol_table = self.config['nt_symbols'], constraints = constraints):

                filename = str(file[1].file_name_with_device() or '')

                if "system32\\tasks\\" in filename.lower() and (('system32\\tasks\\microsoft' not in filename.lower() or self.config.get('verbose', None))):
                    tasks.append((file[1], filename))
                    vollog.debug("Found task: 0x{0:x} {1}".format(file[1].vol.offset,filename))
            for file, name in tasks:
                try:
                    for data in dumpfiles.DumpFiles.process_file_object(context = self.context, primary_layer_name = self.config['primary'], open_method = self.open, file_obj = file):
                        f = open(data[3], "br")
                        task_xml = f.read()
                        f.close()
                        os.remove(data[3])
                        parsed = self.parse_task_xml(task_xml,name)
                        if parsed:
                            args = parsed['Actions']['Exec'].get("Arguments", None)
                            if args:
                                parsed['Actions']['Exec']['Command'] += " {}".format(args)
                            pids = self.find_pids_for_imagepath(parsed['Actions']['Exec']['Command'])
                            parsed_tasks.append((name.split('\\')[-1], parsed, task_xml, pids))
                except Exception as e:
                    vollog.debug('parsing() failed to complete. Exception: {0} {1}'.format(type(e).__name__, e.args))

        except Exception as e:
            vollog.warning('get_tasks() failed to complete. Exception: {0} {1}'.format(type(e).__name__, e.args))

        vollog.debug('Finished get_tasks()')
        return parsed_tasks

    def parse_task_xml(self, xml, f_name):
        raw = xml
        xml = re.sub(b'\x00\x00+', b'', xml) + b'\x00'
        if xml:
            try:
                xml = xml.decode('utf-16')
                xml = re.sub(r"<Task(.*?)>", "<Task>", xml)
                xml = xml.encode('utf-16')
                root = ET.fromstring(xml)
                d = {}

                for e in root.findall("./RegistrationInfo/Date"):
                    d['Date'] = e.text or ''
                for e in root.findall("./RegistrationInfo/Description"):
                    d['Description'] = e.text or ''
                for e in root.findall("./Actions"):
                    d['Actions'] = self.visit_all_children(e)
                for e in root.findall("./Settings/Enabled"):
                    d['Enabled'] = e.text or ''
                for e in root.findall("./Settings/Hidden"):
                    d['Hidden'] = e.text or ''
                for t in root.findall("./Triggers/*"):
                    d['Triggers'] = self.visit_all_children(t)

                if not d.get("Actions", {}).get('Exec', {}).get("Command", False):
                    return None

                return d
            except UnicodeDecodeError as e:
                vollog.warning('Error while parsing the following task: {}'.format(f_name))
                vollog.debug('UnicodeDecodeError for: {}'.format(repr(raw)))
    
    def visit_all_children(self, node):
        d = {}
        for c in node:
            d[c.tag] = self.visit_all_children(c)

        if node.text:
            if node.text.strip(' \t\n\r'):
                d = node.text.strip(' \t\n\r')
        return d



    # Winlogon Notification packages are supported in pre-Vista versions of Windows only
    # See: http://technet.microsoft.com/fr-fr/library/cc721961(v=ws.10).aspx
    # returns [] or a list of tuples from parse_winlogon_registration_key()
    def get_winlogon_registrations(self):

        vollog.debug('Started get_winlogon_registrations()')
        results = []
        notify_key = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify"
        hive = None
        try:
            hive = next(hivelist.HiveList.list_hives(context = self.context,
                                                    base_config_path = self.config_path,
                                                    layer_name = self.config['primary'],
                                                    symbol_table = self.config['nt_symbols'],
                                                    hive_offsets = None,
                                                    filter_string = 'software'))
            
            for subkey in hive.get_key(notify_key).get_subkeys():
                parsed_entry = self.parse_winlogon_registration_key(subkey)
                if parsed_entry and (self.config.get('verbose', None) or (parsed_entry[0].split('\\')[-1] not in WINLOGON_REGISTRATION_KNOWN_DLLS)):
                    results.append(parsed_entry)

        except Exception as e:
            vollog.warning('get_winlogon_registrations() failed to complete. Exception: {0} {1}'.format(type(e).__name__, e.args))

        if hive is not None:
            self.context.layers.del_layer(hive.name)

        vollog.debug('Finished get_winlogon_registrations()')
        return results

    # Returns None or (str(dllname), [(str(trigger)),str(event))], key.LastWriteTime, key path, [int(pids)])
    def parse_winlogon_registration_key(self, key):

        dllname = ""
        events = []
        pids = []
        key_path = key.get_key_path()

        try:
            for value in key.get_values():
                val_name = value.get_name()
                val_data = value.decode_data() if int == type(value.decode_data()) else str(value.decode_data() ,"utf-16").replace('\x00', '')

                if val_name.lower() == 'dllname':
                    dllname = val_data
                    pids = self.find_pids_for_imagepath(dllname)
                elif val_name in WINLOGON_NOTIFICATION_EVENTS:
                    events.append((val_name, val_data))

        except Exception as e:
            vollog.warning('Failed while parsing {}. Exception: {} {}'.format(key_path, type(e).__name__, e.args))

        if dllname:
            return (dllname, events, self.dateString(key), key_path, pids)


    # Returns [] or a list of tuples(val_name, val_data, key.LastWriteTime, expected_val_data, [int(pids)])
    def get_winlogon(self):

        vollog.debug('Started get_winlogon()')
        winlogon = []
        winlogon_key_path="Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
        hive = None

        try:
            hive = next(hivelist.HiveList.list_hives(context = self.context,
                                                    base_config_path = self.config_path,
                                                    layer_name = self.config['primary'],
                                                    symbol_table = self.config['nt_symbols'],
                                                    hive_offsets = None,
                                                    filter_string = 'software'))

            key = hive.get_key(winlogon_key_path)
            
            if key:
                for value in key.get_values():
                    val_name = value.get_name()
                    val_data = value.decode_data() if int == type(value.decode_data()) else str(value.decode_data() ,"utf-16").replace('\x00', '')

                    if val_data and val_name in WINLOGON_COMMON_VALUES:
                        pids = self.find_pids_for_imagepath(val_data)
                        winlogon.append((val_name, val_data, self.dateString(key), WINLOGON_COMMON_VALUES[val_name], winlogon_key_path, pids))    

        except Exception as e:
            vollog.warning('get_winlogon() failed to complete. Exception: {} {}'.format(type(e).__name__, e.args))

        if hive is not None:
            self.context.layers.del_layer(hive.name)

        vollog.debug('Finished get_winlogon()')
        return winlogon
    
    
    # Returns [] or a list of tuples from parse_service_key()
    def get_services(self):

        vollog.debug('Started get_services()')
        listHive = []
        results = []
        hive_key_list = []
        service_key_path = "{}\\Services".format(self.currentcs)

        try:

            hiveList = hivelist.HiveList.list_hives(context = self.context,
                                                    base_config_path = self.config_path,
                                                    layer_name = self.config['primary'],
                                                    symbol_table = self.config['nt_symbols'],
                                                    hive_offsets = None,
                                                    filter_string = 'system')

            for hive in hiveList:
                try:
                    test = hive.get_key(service_key_path)
                    for service_sk in test.get_subkeys():
                        try:
                            parsed_service = self.parse_service_key(service_sk,hive)
                            if parsed_service and (self.config.get('verbose', None) or 'system32' not in parsed_service[5].lower()):
                                results.append(parsed_service)
                        except Exception as e:
                            vollog.warning('unable to parse service. Exception: {0} {1}'.format(type(e).__name__, e.args))
                    
                except Exception as e:
                    vollog.debug('Cannot Retrive key. Exception: {0} {1}'.format(type(e).__name__, e.args))

                self.context.layers.del_layer(hive.name)
        
        except Exception as e:
            vollog.warning('get_services() failed to complete. Exception: {0} {1}'.format(type(e).__name__, e.args))

        vollog.debug('Finished get_services()')
        return results


    def parse_service_key(self, hive_key, hive):
        dict_values = {}
        try:
            for values in hive_key.get_values():
                try:
                    dict_values[values.get_name()] = values.decode_data() if int == type(values.decode_data()) else str(values.decode_data(),"utf-16").replace('\x00', '')
                except Exception as e:
                    vollog.warning('Failed while parsing. Exception: {0} {1}, tried to decode {2}, storing raw value...'.format(type(e).__name__, e.args,values.decode_data()))
                    dict_values[values.get_name()] = values.decode_data()

            if dict_values:
                image_path = dict_values.get("ImagePath", "")
                display_name = dict_values.get("DisplayName","")
                service_dll = dict_values.get("ServiceDll","")
                mains = dict_values.get("ServiceMain","")
                startup = int(dict_values.get("Start", -1))
                service_type = int(dict_values.get("Type", -1))
                timestamp = self.dateString(hive_key)
                key_path = hive_key.get_key_path()

                if not image_path or startup not in [0, 1, 2]:
                    return None

                if "svchost.exe -k" in image_path.lower() or SERVICE_TYPES[service_type] == 'Share_Process':
                    for param in hive_key.get_subkeys():
                        if 'Parameters' in param.get_name() and not service_dll:
                            timestamp = self.dateString(param)
                            try:
                                for values_param in param.get_values():
                                    if "ServiceDll" == values_param.get_name():
                                        service_dll = str(values_param.decode_data(),"utf-16").replace('\x00', '')
                                    if "ServiceMain" == values_param.get_name():
                                        mains = str(values_param.decode_data(),"utf-16").replace('\x00', '')
                            except:
                                vollog.warning('Failed while parsing key {0}. Exception: {1} {2}'.format(hive_key.get_name(),type(e).__name__, e.args))


                        if not service_dll and '@' in display_name:
                            timestamp = self.dateString(hive_key)
                            service_dll = display_name.split('@')[1].split(',')[0]
                
                if service_dll:
                    pids = self.find_pids_for_imagepath(service_dll)
                    if mains:
                        service_dll = "{} ({})".format(service_dll, mains)
                else:
                    pids = self.find_pids_for_imagepath(image_path)
                
                res = (key_path, timestamp, display_name, SERVICE_STARTUP[startup], SERVICE_TYPES[service_type], image_path, service_dll, pids)
     
                vollog.info(res)
                return res
            return None
                              
        except Exception as e:
            vollog.debug('Failed while parsing key {0}. Exception: {1} {2}'.format(hive_key.get_name(),type(e).__name__, e.args))

    # Returns [] or a list of tuples from parse_activesetup_keys()
    def get_activesetup(self):

        vollog.debug('Started get_activesetup()')
        results = []
        for hive in hivelist.HiveList.list_hives(context = self.context,
                                                    base_config_path = self.config_path,
                                                    layer_name = self.config['primary'],
                                                    symbol_table = self.config['nt_symbols'],
                                                    hive_offsets = None,
                                                    filter_string = 'software'):

            try:
                if hive.get_key(ACTIVE_SETUP_KEY):
                    for subkey in hive.get_key(ACTIVE_SETUP_KEY).get_subkeys():
                        r = self.parse_activesetup_keys(subkey)
                        if r:
                            results.append(r)
                
            except Exception as e:
                vollog.warning('get_activesetup() failed to complete. Exception: {0} {1}, ignoring...'.format(type(e).__name__, e.args))

            self.context.layers.del_layer(hive.name)
        vollog.debug('Finished get_activesetup()')

        return results

    # Returns None or a tuple(exe path, subkey.LastWriteTime, key path, [int(pids)])
    def parse_activesetup_keys(self, subkey):
        stub_path_val = ""
        key_path = subkey.get_key_path() or str(subkey.get_name())
        try:
            for values in subkey.get_values():
                if 'StubPath' in values.get_name():
                    stub_path_val = values.decode_data()
                    stub_path_val = str(stub_path_val or '',"utf-16").replace('\x00', '')
                    break
        except Exception as e:
            vollog.warning('Failed while parsing {}. Exception: {} {}'.format(key_path, type(e).__name__, e.args))

        if stub_path_val:
            pids = self.find_pids_for_imagepath(stub_path_val)
            last_write_time = self.dateString(subkey)
            return (stub_path_val, last_write_time, key_path, pids)

    # Returns [] or a list of tuples from parse_sdb_key()
    def get_sdb(self):

        vollog.debug('Started get_sdb()')
        results = []

        for hive in hivelist.HiveList.list_hives(context = self.context,
                                                    base_config_path = self.config_path,
                                                    layer_name = self.config['primary'],
                                                    symbol_table = self.config['nt_symbols'],
                                                    hive_offsets = None,
                                                    filter_string = 'software'):

            try:
                for subkey in hive.get_key(APPCOMPAT_SDB_KEY).get_subkeys():
                    parsed_sdb_entry = self.parse_sdb_key(subkey)
                    if parsed_sdb_entry:
                        results.append(parsed_sdb_entry)

            except Exception as e:
                vollog.warning('get_sdb() failed to complete. Exception: {0} {1}'.format(type(e).__name__, e.args))

            self.context.layers.del_layer(hive.name)

        vollog.debug('Finished get_sdb()')
        return results

    #Returns None or a tuple(exe, db_path, subkey.LastWriteTime, key path, [int(pids)])
    def parse_sdb_key(self, subkey):

        key_path = subkey.get_key_path() or str(subkey.get_name())
        desc = ''
        try:         
            for values in subkey.get_values():
                if 'DatabaseDescription' in values.get_name():
                    desc = sanitize_path(str(values.decode_data() or '',"utf-16").replace('\x00', ''))
                if 'DatabasePath' in values.get_name():
                    db_path = sanitize_path(str(values.decode_data() or '',"utf-16").replace('\x00', ''))

            pids = self.find_pids_for_imagepath(desc)
        except Exception as e:
            vollog.warning('Failed while parsing {}. Exception: {} {}'.format(key_path, type(e).__name__, e.args))

        if desc:
            last_write_time = self.dateString(subkey)
            vollog.info((desc, db_path, last_write_time, key_path, pids))
            return (desc, db_path, last_write_time, key_path, pids)

    # Returns [] or a list of tuples from parse_autoruns_key()
    def get_autoruns(self):

        results = []
        hive_key_list = []

        listHive = []

        try:


            # Gather all software run keys
            hive = next(hivelist.HiveList.list_hives(context = self.context,
                                                    base_config_path = self.config_path,
                                                    layer_name = self.config['primary'],
                                                    symbol_table = self.config['nt_symbols'],
                                                    hive_offsets = None,
                                                    filter_string = 'software'))

            listHive.append(hive)

            # Gather all software run keys
            for run_key in SOFTWARE_RUN_KEYS:
                try:    
                        hive_key_list.append([hive.get_name(),hive.get_key(run_key)])

                except Exception as e:
                    vollog.debug('Unable to get key. Exception: {0} {1}'.format(type(e).__name__, e.args))


            # Gather all ntuser run keys
            for hive in hivelist.HiveList.list_hives(context = self.context,
                                                    base_config_path = self.config_path,
                                                    layer_name = self.config['primary'],
                                                    symbol_table = self.config['nt_symbols'],
                                                    hive_offsets = None,
                                                    filter_string = 'ntuser.dat'):

                listHive.append(hive)
                for run_key in NTUSER_RUN_KEYS:
                    try:    
                            hive_key_list.append([hive.get_name(),hive.get_key(run_key)])

                    except Exception as e:
                        vollog.debug('Unable to get key. Exception: {0} {1}'.format(type(e).__name__, e.args))


            for hive_key_dict in hive_key_list:
                hive_name = hive_key_dict[0] # Hive name
                hive_key = hive_key_dict[1] # Hive key
    
                try:
                    for value in hive_key.get_values():
                        key_path = hive_key.get_key_path()
                        last_write_time = self.dateString(hive_key)
                        val_name = value.get_name()
                        data_str = str(value.decode_data(),"utf-16").replace('\x00', '')
                        pids = self.find_pids_for_imagepath(data_str)
                        results.append((data_str,hive_name,key_path,last_write_time,val_name,pids))
                except Exception as e:
                    vollog.debug('Exception: {0} {1}'.format(type(e).__name__, e.args))



        except Exception as e:
            vollog.warning('get_autoruns() failed to complete. Exception: {0} {1}'.format(type(e).__name__, e.args))
            

        # Free used hives from the layers
        for hive in listHive:
            self.context.layers.del_layer(hive.name)
        
        return results

    def peb_load_order_modules(self,peb):
        try:
            for entry in peb.Ldr.InLoadOrderModuleList.to_list("{}{}_LDR_DATA_TABLE_ENTRY".format(self.config['nt_symbols'], constants.BANG),"InLoadOrderLinks"):
                yield entry
        except Exception as e:
                vollog.debug('Exception: {0} {1}'.format(type(e).__name__, e.args))


    def get_dll_list(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        task_objects = pslist.PsList.list_processes(self.context,
                                                   self.config['primary'],
                                                   self.config['nt_symbols'],
                                                   filter_func = filter_func)
        for task in task_objects:
            try:
                peb = task.get_peb()
                self.process_dict[int(task.UniqueProcessId)] = (peb, [m for m in self.peb_load_order_modules(peb)])

            except Exception as e:
                vollog.debug('Exception: {0} {1}'.format(type(e).__name__, e.args))

            #print(type(task))
            #self.context.layers.del_layer(task)

    
    # Matches a given module (executable, DLL) to a running process by looking either
    # in the CommandLine parameters or in the loaded modules
    def find_pids_for_imagepath(self, module):
        pids = []
        module = sanitize_path(module)
        if module:
            for pid in self.process_dict:
                # case where the image path matches the process' command-line information
                if self.process_dict[pid][0]:
                    try: 
                        cmdline = self.process_dict[pid][0].ProcessParameters.CommandLine.get_string()

                        if module in sanitize_path(str(cmdline or '[no cmdline]')):
                            pids.append(pid)
                    except Exception as e:
                        vollog.debug('Exception: {0} {1}'.format(type(e).__name__, e.args))

                # case where the module is actually loaded process (case for DLLs loaded by services)
                for dll in self.process_dict[pid][1]:
                    try:
                        if module in sanitize_path(str(dll.FullDllName.get_string() or '[no dllname]')):
                            pids.append(pid)
                    except Exception as e:
                        vollog.debug('Exception: {0} {1}'.format(type(e).__name__, e.args))
        
        return list(set(pids))


    # Returns [] or a list of tuples(dll, key path, key.LastWriteTime, [int(pids)])
    def get_appinit_dlls(self):

        vollog.debug('Started get_appinit_dlls()')
        key_path="Microsoft\\Windows NT\\CurrentVersion\\Windows"
        results = []

        try:
            hive = next(hivelist.HiveList.list_hives(context = self.context,
                                                    base_config_path = self.config_path,
                                                    layer_name = self.config['primary'],
                                                    symbol_table = self.config['nt_symbols'],
                                                    hive_offsets = None,
                                                    filter_string = 'software'))

            key = hive.get_key(key_path)
            for values in key.get_values():
                if "AppInit_DLLs" == values.get_name():
                    appinit_values = str(values.decode_data(),"utf-16")

        except Exception as e:
            vollog.warning('get_appinit_dlls() failed to complete. Exception: {} {}'.format(type(e).__name__, e.args))

        else:
            if appinit_values:
                # Split on space or comma: https://msdn.microsoft.com/en-us/library/windows/desktop/dd744762(v=vs.85).aspx
                appinit_dlls = str(appinit_values).replace('\x00', '').replace(',', ' ').split(' ')
                results = [(dll, key_path, self.dateString(key), "AppInit_DLLs", self.find_pids_for_imagepath(dll)) for dll in appinit_dlls if dll]

        vollog.debug('Finished get_appinit_dlls()')
        self.context.layers.del_layer(hive.name)
        return results
                

    def get_currentcontrolset(self):
        currentControlset = 1
        self.currentcs = "ControlSet"
                                                 
        for hive in hivelist.HiveList.list_hives(context = self.context,
                                                 base_config_path = self.config_path,
                                                 layer_name = self.config['primary'],
                                                 symbol_table = self.config['nt_symbols'],
                                                 hive_offsets = None,
                                                 filter_string = '\\REGISTRY\\MACHINE\\SYSTEM'):
            
            try:
                for keylist in hive.get_key(key="Select").get_values():
                    if "Current" in keylist.get_name():    
                        currentControlset = str(int(keylist.decode_data()))
                        for i in range(3 - len(currentControlset)):
                            currentControlset = "0" + currentControlset
                        self.currentcs += currentControlset
                        break

            except Exception as e:
                vollog.debug('Exception: {0} {1}'.format(type(e).__name__, e.args))
                print(traceback.format_exc())
                exit()
                
            self.context.layers.del_layer(hive.name)

    def get_unified_output_data(self):
        data =[]
        for exe_path, hive, key, timestamp, val_name, pids in self.autoruns:
            data.append([exe_path,
                   'Autoruns',
                   timestamp,
                   val_name,
                   ", ".join([str(p) for p in pids]),
                   hive,
                   key,
                   val_name,
                   ""])
        for exe_path, key, timestamp, val_name, pids in self.appinit_dlls:
            data.append([exe_path,
                   'AppInit Dlls',
                   timestamp,
                   '-',
                   ", ".join([str(p) for p in pids]),
                   "Windows/System32/config/SOFTWARE",
                   key,
                   val_name,
                   ""])
        for exe_path, events, timestamp, key, pids in self.winlogon_registrations:
            data.append([exe_path,
                   'Winlogon (Notify)',
                   timestamp,
                   'Hooks: {0}'.format(", ".join([e[1] for e in events])),
                   ", ".join([str(p) for p in pids]),
                   "Windows/System32/config/SOFTWARE",
                   key,
                   "Dllname",
                   ""])
        for val_name, exe_path, timestamp, common_value, key, pids in self.winlogon:
            data.append([exe_path,
                   'Winlogon ({})'.format(val_name),
                   timestamp,
                   "Default value: {}".format(common_value),
                   ", ".join([str(p) for p in pids]),
                   "Windows/System32/config/SOFTWARE",
                   key,
                   val_name,
                   ""])
        for key, timestamp, display_name, start, type, exe_path, entry, pids in self.services:
            data.append([exe_path,
                   'Services',
                   timestamp,
                   "{0} - {1} ({2} - {3})".format(key.split('\\')[-1], display_name, type, start),
                   ", ".join([str(p) for p in pids]),
                   "Windows/System32/config/SYSTEM",
                   key,
                   "",
                   entry])
        for name, task, task_xml, pids in self.tasks:
            data.append([task['Actions']['Exec']['Command'],
                   'Scheduled Tasks',
                   task.get('Date', ""),
                   "{} ({})".format(name, task.get('Description', "N/A")),
                   ", ".join([str(p) for p in pids]),
                   "",
                   "",
                   "",
                   ""])
        for exe_path, timestamp, key, pids in self.activesetup:
            data.append([exe_path,
                   "Active Setup",
                   timestamp,
                   "-",
                   ", ".join([str(p) for p in pids]),
                   "Windows/System32/config/SOFTWARE",
                   key,
                   "StubPath",
                   ""])
        for desc, exe_path, timestamp, key, pids in self.sdb:
            data.append([exe_path,
                   "SDB",
                   timestamp,
                   desc,
                   ", ".join([str(p) for p in pids]),
                   "Windows/System32/config/SOFTWARE",
                   key,
                   "",
                   ""])
        return data

    def run(self):
        self.process_dict = {}
        self.autoruns = []
        self.services = []
        self.appinit_dlls = []
        self.winlogon = []
        self.winlogon_registrations = []
        self.tasks = []
        self.activesetup = []
        self.sdb = []

        os_major = info.Info.get_ntheader_structure(context = self.context, 
                                                    layer_name=self.config['primary'],
                                                    config_path = self.config_path).OptionalHeader.MajorOperatingSystemVersion

        asep_list = ['autoruns', 'services', 'appinit', 'winlogon', 'tasks', 'activesetup', 'sdb']
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        self.get_dll_list()
        if os_major < 6:
            self.currentcs = "ControlSet001"
        else:
            self.get_currentcontrolset()

        if self.config.get('asep', None):
            asep_list = self.config.get('asep', None)
            print(asep_list)

        if self.config.get('r', None):
            print(self.config.get('r', None))

        # Scan for ASEPs and populate the lists
        if 'autoruns' in asep_list:
            self.autoruns = self.get_autoruns()
        if 'services' in asep_list:
            self.services = self.get_services()
        if 'appinit' in asep_list:
            self.appinit_dlls = self.get_appinit_dlls()
        if 'winlogon' in asep_list:
            self.winlogon = self.get_winlogon()
            if os_major == 5:
                self.winlogon_registrations = self.get_winlogon_registrations()
        if 'tasks' in asep_list:
            self.tasks = self.get_tasks()
        if 'activesetup' in asep_list:
            self.activesetup = self.get_activesetup()
        if 'sdb' in asep_list:
            self.sdb = self.get_sdb()

        vollog.debug(layer_items for layer_items in self.context.layers.items())
        
        data = self.get_unified_output_data()
        
        return renderers.TreeGrid([("Executable", str),
                        ("Source", str),
                        ("Last write time", str),
                        ("Details", str),
                        ("PIDs", str),
                        ("Hive", str),
                        ("Key", str),
                        ("Name", str),
                        ("Share Process Dll", str)],
                        self.generator(data))

    def generator(self, data):
        """This yields data according to the unified output format"""
        for executable, source, lastWriteTime, details, pids, hive, key, name, spDllPath in data:
            yield (0, [str(executable), str(source), str(lastWriteTime), str(details), str(pids), str(hive), str(key), str(name), str(spDllPath)])
