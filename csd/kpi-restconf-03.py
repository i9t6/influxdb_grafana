#!/usr/bin/python
import csv
import re
import sys
import requests
import time
import paramiko
import logging
from datetime import datetime
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

import urllib3
urllib3.disable_warnings()

#Colums of CSV file with conditions
conditions_index = [2,3,4]

# NSO info
nso_srv = {'host':'172.16.1.122','port':'2022','username':'admin','password':'admin','hostkey_verify':False}
#nso_srv = {'host':'10.57.236.6','port':'2022','username':'hoyosrc','password':'Sickness123!','hostkey_verify':False}
base_url = f"https://{nso_srv['host']}:7443/restconf/data"
base_url_ops = f"https://{nso_srv['host']}:7443/restconf/operations"
headers = {'Accept': 'application/yang-data+json','Content-Type': 'application/yang-data+json','Authorization': 'Basic YWRtaW46YWRtaW4='}
#headers = {'Accept': 'application/yang-data+json','Content-Type': 'application/yang-data+json','Authorization': 'Basic aG95b3NyYzpTaWNrbmVzczEyMyE='}


# For licensing information
nso_srv_lics = {'host':nso_srv['host'], 'port_cli':'2024','username':nso_srv['username'] , 'password':nso_srv['password']}

# You can generate a Token from the "Tokens Tab" in the UI
influx_srv = {'url':'http://172.16.1.122:8086','token':'P4By5dsQDzgqtZAGrGSUZrrJo22ALYM3-SkdlWYPji8aJK2DtW9o0vXP1N5cEq69TPL8mKPxr4mxxYfJdSFKNA=='}
# Influx bucket & org
influx_db_info  = ('css','cisco')

# Search map for priority definitions
search_map = {'ned':"device['device-type']['cli']['ned-id']",'location':"device['location']['name']",
              'sname':"var_instance['name']",'name':"device['name']",'address':"device['address']",
              'authgroup':"device['authgroup']",'service-list':"device['service-list']"}

date = datetime.now().date().strftime('%Y-%d-%m')
console_formartter = logging.Formatter('%(asctime)s:module:%(module)s>> %(message)s')
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(console_formartter)
my_logger = logging.getLogger()
my_logger.addHandler(console_handler)


def find_today_changes(var_file_list):
    date = datetime.now().date().strftime('%Y-%m-%d')
    final_list = []
    for file in var_file_list:
        #print(f"{file['date']} {date}")
        if file['date'].split(' ')[0] == date:
            final_list.append(file)
    return final_list
    

def find_service(var_content):
    srv_dic = services_get_dict()
    for service in srv_dic.keys():
        if service in var_content:
            return service
    if 'device' in var_content:
        return 'device'
    else:
        return 'other'

def get_rollbacks_info():
    url = f"{base_url}/tailf-rollback:rollback-files"
    my_logger.warning(f"\n {url}")
    response = requests.request("GET", url, headers=headers, verify=False)
    file_list = find_today_changes(response.json()['tailf-rollback:rollback-files']['file'])
    srv_dic = services_get_dict()
    for srv in srv_dic:
        srv_dic[srv] = 0
    srv_dic['device'] = 0
    srv_dic['other'] = 0
    for file in file_list:
        url2 = f"{base_url_ops}/tailf-rollback:rollback-files/get-rollback-file"
        payload = f"""{{"input": {{"id": "{file['id']}" }} }}"""     
        response = requests.request("POST", url2, data=payload, headers=headers, verify=False)
        service = find_service(response.json()['tailf-rollback:output']['content'])
        srv_dic[service] += 1
        file['service'] = service
        my_logger.warning(f"{file['id']} {file['creator']} {file['date']} {file['via']} {file['service']} {len(file_list)}")
    
    return srv_dic

def services_get_dict():
    service_dict={}
    url = f"{base_url}/tailf-ncs-monitoring:ncs-state/internal/callpoints/servicepoint?depth=1"
    response = requests.request("GET", url, headers=headers, verify=False)
    for srv in response.json()['tailf-ncs-monitoring:servicepoint']:
        service_dict[ srv['id'].replace('-servicepoint','')] = []
    return service_dict

def instance_set_priority(var_service, var_instance, var_priorities):
    for condition in var_priorities:
        if var_service in condition[0]:
            flag = 1
            for index in conditions_index:
                if not condition[index] == '':
                    if 'device' in condition[index]:
                        if not type(var_instance['device']) == type([]):
                            dev_list = [var_instance['device']]
                        else:
                            dev_list = var_instance['device']
                        for dev in dev_list:
                            url = f"{base_url}/tailf-ncs:devices/device={dev}?fields=name;address;device-type;location;service-list;authgroup&depth=2"
                            response = requests.request("GET", url, headers=headers, verify=False)
                            device = response.json()['tailf-ncs:device'][0]
                            flag = device_try_condition(flag, device, condition[index] )
                    else:
                        eval_string = condition[index]
                        my_logger.warning(f"\n eval_string: {eval_string}")
                        if eval(eval_string):
                            flag = flag and 1
                        else:
                            flag = flag and 0
                else:
                    flag = flag and 1
            if flag:
                return condition[1]
    return '5'

def find_keys_id(var_keys, var_instance, *var_key):
    my_logger.warning(f"\n -----{var_keys} {var_instance}")
    if len(var_keys) == 0:
            return { var_key : {'priority': '5', 'devices': []}}
    elif 'modified' in var_keys[0]:
        return { var_key : {'priority': '5', 'devices': var_instance['device-list']}}
    else:
        if len(var_key) == 0:
            return find_keys_id(var_keys[1:],var_instance, var_instance[var_keys[0]] )
        else:
            return find_keys_id(var_keys[1:],var_instance, *var_key + (var_instance[var_keys[0]],)  )

def services_get_summary(var_service_dict, var_priorities):
    url = f"{base_url}?depth=2"
    response = requests.request("GET", url, headers=headers, verify=False)
    for service, srv_info in var_service_dict.items():
        instances_list = []
        flag = 1
        my_logger.warning(f"\n Service: {service}")
        for key in response.json()['ietf-restconf:data']['tailf-ncs:services'].keys():
            try:
                re.search(rf":{service}$",key).group(0)
            except:
                try:
                    re.search(rf":{service.replace('-','_')}$",key).group(0)
                except:
                    continue
            url2 = f"{base_url}/tailf-ncs:services/{key}"
            my_logger.warning(f"\n URL: {url2}")
            response_detailed = requests.request("GET", url2, headers=headers, verify=False)
            instances_list = response_detailed.json()[key]
            flag = 0
            break
        if flag:
            for key in response.json()['ietf-restconf:data'].keys():
                try:
                    re.search(rf":{service}$",key).group(0)
                except:
                    try:
                        re.search(rf":{service.replace('-','_')}$",key).group(0)
                    except:
                        continue
                url2 = f"{base_url}/{key}"
                my_logger.warning(f"\n URL: {url2}")
                response_detailed = requests.request("GET", url2, headers=headers, verify=False)
                instances_list = response_detailed.json()[key]
                flag = 0
                break
        my_logger.warning(f"\n Instace list \n{instances_list}\n")
        if not type(instances_list) == type([]):
            my_logger.info(f"\n \t\t Instance++ {service} \t {instances_list} \n")
            priority = instance_set_priority(service, instances_list, var_priorities )
            temp_dict = find_keys_id(list(instances_list),instances_list)
            for key in temp_dict.keys():
                    temp_dict[key]['priority'] = priority
            srv_info.append(temp_dict)    
        else:
            for instance in instances_list:
                my_logger.info(f"\n \t\t Instance-- {service} \t {instance} \n")
                priority = instance_set_priority(service, instance , var_priorities)
                temp_dict = find_keys_id(list(instance.keys()),instance)
                for key in temp_dict.keys():
                    temp_dict[key]['priority'] = priority
                srv_info.append(temp_dict)

    table = [['Service','p1','q1','p2','q2','p3','q3','p4','q4','p5','q5']]
    my_logger.warning(f"\n {'= services with priorities ='*10} \n {var_service_dict} \n")

    for srv, info in var_service_dict.items():
        if len(info) == 0:
            table.append([srv]+[0,0,0,0,0,0,0,0,0,0])
            continue
        temp_dir={}
        for column in list(range(1,6)):
            temp_dir[str(column)] = 0
            temp_dir[f"q{str(column)}"] = 0
        for instance in info:
            for data in instance.values():
                temp_dir[data['priority']] += 1
                if type(data['devices']) == type([]):
                    temp_dir[f"q{data['priority']}"] += len(data['devices'])
                else:
                    temp_dir[f"q{data['priority']}"] += 1
        table.append([srv]+list(temp_dir.values()))
    return [var_service_dict,table]

def read_priorities(var_file):
    priorities_list_device = []
    priorities_list_service = []
    with open(var_file) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        priorities_temp = list(csv_reader)
    for line in priorities_temp[1:]:
        if '#' in line[0][0]:
            continue
        elif 'device' in line[0]:
            priorities_list_device.append(line)
        elif not 'device' in line[0]:
            priorities_list_service.append(line)
        else:
            continue
    return [priorities_list_device,priorities_list_service]

def fix_condition(var_device_priorities):
    for condition in var_device_priorities:
        for i in conditions_index:            
            if not condition[i] == '':
                flag = 1
                # search_map in top variables definition
                for code,new_code in search_map.items():
                    if code in condition[i]:
                        condition[i] = condition[i].replace(code, new_code)
                        flag = 0
                        break
                if flag:
                    condition[i] = condition[i].replace(condition[i].split(' ')[-1],f"var_instance['{condition[i].split(' ')[-1]}']" )
    return var_device_priorities

def device_get_and_set_priority(var_condition_list):
    devices_dict = {}
    url = f"{base_url}/tailf-ncs:devices/device?fields=name;address;device-type;location;service-list;authgroup&depth=2"
    my_logger.warning(f"\n{url}\n")
    response = requests.request("GET", url, headers=headers, verify=False)
    my_logger.warning(f"\nThere are {len(response.json()['tailf-ncs:device'])} devices\n")
    for device in response.json()['tailf-ncs:device']:
        for condition in var_condition_list:
            flag = 1
            for index in conditions_index:
                if not condition[index] == '':
                    flag = device_try_condition(flag, device, condition[index])
                else:
                    flag = flag and 1
                    my_logger.info(device['name'], condition[index],  flag)
            if flag:
                if 'cli' in device['device-type'].keys():
                    devices_dict[device['name']] = [condition[1], device['device-type']['cli']['ned-id'].split(':')[0]]
                elif 'netconf' in device['device-type'].keys():
                    devices_dict[device['name']] = [condition[1], device['device-type']['netconf']['ned-id'].split(':')[0]]
                else:
                    devices_dict[device['name']] = [condition[1], "ned-other"]
                break
    return devices_dict

def devices_summary_wPriority(var_devices_list):
    table = [['devices','p1','p2','p3','p4','p5']]
    summary_wPriority_by_ned = {}
    summary_wPriority_by_priority = {}
    for info in var_devices_list.values():
        try:
            summary_wPriority_by_ned[info[1]][info[0]] += 1
        except:
            try:
                summary_wPriority_by_ned[info[1]][info[0]] = 1
            except:
                summary_wPriority_by_ned[info[1]] = {info[0]:1}
        my_logger.info(summary_wPriority_by_ned)

    for ned, info in summary_wPriority_by_ned.items():
        temp_list = []
        temp_list.append(ned)
        for column in list(range(1,6)):
            try:
                temp_list.append(info[str(column)])
            except:
                temp_list.append(0)
        table.append(temp_list)

    for ned, info in summary_wPriority_by_ned.items():
        for severity, quantity in info.items():
            try:
                summary_wPriority_by_priority[severity][ned] += quantity
            except:
                try:
                    summary_wPriority_by_priority[severity][ned] = quantity
                except:
                    summary_wPriority_by_priority[severity] = {ned:quantity}
            my_logger.info(summary_wPriority_by_priority)

    return [summary_wPriority_by_ned,summary_wPriority_by_priority,table]
        
def devices_summary_short(var_summary_wPriority_by_priority):
    summary_by_priority = {'1':0,'2':0,'3':0,'4':0,'5':0}
    for priority in summary_by_priority:
        try:
            neds = var_summary_wPriority_by_priority[priority]
            for qty in neds.values():
                summary_by_priority[priority] += qty
        except:
            continue
    return summary_by_priority

def write_to_influx(var_type, var_summary):
    # print summary before write to DB
    if not var_type == 'licenses':
        my_logger.warning(f"{var_type} {var_summary}")
        #print(var_type, var_summary)
        my_logger.error(f"{var_type} {var_summary}")
        for l in var_summary:
            my_logger.warning(f"{l} ")

    try:
        client = InfluxDBClient(**influx_srv)
        write_api = client.write_api(write_options=SYNCHRONOUS)
        if var_type == 'devices':
            for row in var_summary[1:]:
                data = f"priorities,ned={row[0]} p1={row[1]},p2={row[2]},p3={row[3]},p4={row[4]},p5={row[5]}"
                my_logger.warning(f"{data}")
                write_api.write(*influx_db_info,data)
            return 'ok'
        elif var_type == 'services':
            for row in var_summary[1:]:
                data = f"services,service={row[0]} p1={row[1]},q1={row[2]},p2={row[3]},q2={row[4]},p3={row[5]},q3={row[6]},p4={row[7]},q4={row[8]},p5={row[9]},q5={row[10]}"
                my_logger.warning(f"{data}")
                write_api.write(*influx_db_info,data)
            return 'ok'
        elif var_type == 'licenses':
            #If no Smart-license config, NSO-network-element show a Count summary
            if "NSO-network-element" in var_summary.keys():
                data = f"""licenses,license="NSO-network-element" count={var_summary['NSO-network-element']['Count']},status="{var_summary['NSO-network-element']['Status']}" """
            else:
                count = 0 
                for entry in var_summary.values():
                    if 'Count' in entry.keys():
                        count += int(entry['Count'])
                data = f"""licenses,license="NSO-platform-production" count={count},status="{var_summary['NSO-platform-production']['Status']}" """
            #print(data)
            my_logger.error(f"{data}")
            write_api.write(*influx_db_info,data)
            return 'ok'
        elif var_type == 'changes':
            for srv, qty in var_summary.items():
                data = f"""changes,change={srv} qty={qty}"""
                my_logger.warning(f"{data}")
                write_api.write(*influx_db_info,data)
            return 'ok'
    except Exception as e:
        return f'fail: {e}'

def read_and_fix(var_file_csv):
    priorities_raw = read_priorities(var_file_csv)
    my_logger.warning(f"\n {'= priorities_raw devices ='*5} \n {priorities_raw[0]}")
    my_logger.warning(f"\n {'= priorities_raw services='*5} \n {priorities_raw[1]} \n")
    
    conditions = [ fix_condition(priority) for priority in priorities_raw ]
    my_logger.warning(f"\n {'= conditions devices ='*5} \n {conditions[0]} \n")
    my_logger.warning(f"\n {'= conditions services ='*5} \n {conditions[1]} \n")
    return conditions

def devices_info(var_conditions):
    devices_summary_1 = device_get_and_set_priority(var_conditions)
    my_logger.warning(f"\n {'= devices_summary_1 ='*10} \n {devices_summary_1}")
    
    devices_summary_2 = devices_summary_wPriority(devices_summary_1)
    my_logger.warning(f"\n {'= devices_summary_2 / 0 ='*5} \n {devices_summary_2[0]}")
    my_logger.warning(f"\n {'= devices_summary_2 / 1 ='*5} \n {devices_summary_2[1]}")
    my_logger.warning(f"\n {'= devices_summary_2 / 2 ='*5} \n {devices_summary_2[2]}")
    
    devices_summary = devices_summary_short(devices_summary_2[1])
    my_logger.warning(f"\n {'= devices_summary ='*5} \n {devices_summary}")
    
    #print(f'{}')
    my_logger.error(f"{write_to_influx('devices', devices_summary_2[2])}")
    

def device_try_condition(var_flag, var_device, var_condition):
    # device will be used in the eval condition
    device = var_device
    try:
        if eval(var_condition):
            return var_flag and 1
    except:
        if 'ned' in str(var_condition):
            try:
                if eval(var_condition.replace('cli','netconf')):
                    return var_flag and 1
            except:
                return var_flag and 0
    else:
        return var_flag and 0

def services_info(var_conditions):
    service_dict = services_get_dict()
    my_logger.warning(f"\n {'= Service_Dict ='*10} \n {service_dict} \n")

    srv = services_get_summary(service_dict,var_conditions)
    my_logger.warning(f"\n {'=='*10} \n {srv[0]}")
    my_logger.warning(f"\n {'=='*10} \n {srv[1]}")

    #print(f'{write_to_influx("services", srv[1])}')
    my_logger.error(f"{write_to_influx('services', srv[1])}") 

def licenses_get_raw(host, port_cli, username, password):
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port=port_cli, username=username, password=password, look_for_keys=False )
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("switch cli \n show license usage")

    # Close connection.
    output = ssh_stdout.readlines()
    ssh.close()

    licenses_raw = {}
    for line in output:
        if not line == "\r\n":
            if 'Authorization' in line:
                key = line.split(':')[0]
                licenses_raw[key] = {'status':line.split(':')[1][1:-2]}
                continue 
            elif '(' in line:
                key = line.split('(')[1][:-3]
                licenses_raw[key] = {'name':line.split('(')[0][:-1]}
                continue
            licenses_raw[key][line.split(':')[0][2:]]=line.split(':')[1][1:-2]
    return licenses_raw

def licenses_info():
    licenses = licenses_get_raw(**nso_srv_lics)
    #print(write_to_influx('licenses', licenses))
    my_logger.error(f"{write_to_influx('licenses', licenses)}")
    

def changes_info():
    changes_summary = get_rollbacks_info()
    my_logger.warning(f"\n\n {changes_summary} \n\n")
    #print(write_to_influx('changes', changes_summary))
    my_logger.error(f"{write_to_influx('changes', changes_summary)}")

def main():
    #time.sleep(180)
    try:
        verbose = sys.argv[1]
    except:
        verbose = ''
    try:
        file_csv = sys.argv[2]
    except:
        file_csv = "service_priority.csv"
    
    # ERROR < WARNING < INFO
    if 'vv' in verbose:    
        vb = 'INFO'
    elif 'v' in verbose:
        vb='WARNING'
    else:
        vb ='ERROR'
    my_logger.setLevel(eval(f"logging.{vb}"))

    try:
        for i in range(100):
            if (i % 2) == 0:
                text = ""
                seconds = 30
            else:
                text = "-02"
                seconds = 40
            conditions = read_and_fix(f"service_priority{text}.csv")
            my_logger.warning(f"\n\n CSV read completed \n\n")
            devices_info(conditions[0])
            services_info(conditions[1])
            changes_info()
            licenses_info()
            
            time.sleep(seconds)
            #print(i)
            my_logger.error(f"{i}") 
    except Exception as e:
        #print(f"{}")
        my_logger.error(f"{str(e)}")
    finally:
        #print("------ COMPLETE ------")
        my_logger.error(f"------ COMPLETE ------")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass