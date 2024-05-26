from base64 import b64decode
import codecs, json, mimetypes, sys, io
import urllib.request
from urllib.parse import urlencode

from prettytable import PrettyTable as pt
from textwrap import wrap
from uuid import uuid4

import ssl
ssl._create_default_https_context = ssl._create_unverified_context

VAL_WRAP_WIDTH = 40

class MultipartFormdataEncoder(object):
    def __init__(self):
        self.boundary = uuid4().hex
        self.content_type = 'multipart/form-data; boundary={}'.format(self.boundary)

    @classmethod
    def u(cls, s):
        if sys.hexversion < 0x03000000 and isinstance(s, str):
            s = s.decode('utf-8')
        if sys.hexversion >= 0x03000000 and isinstance(s, bytes):
            s = s.decode('utf-8')
        return s

    def iter(self, fields, files):
        """
        fields is a sequence of (name, value) elements for regular form fields.
        files is a sequence of (name, filename, file-type) elements for data to be uploaded as files
        Yield body's chunk as bytes
        """
        encoder = codecs.getencoder('utf-8')
        for (key, value) in fields:
            key = self.u(key)
            yield encoder('--{}\r\n'.format(self.boundary))
            yield encoder(self.u('Content-Disposition: form-data; name="{}"\r\n').format(key))
            yield encoder('\r\n')
            if isinstance(value, int) or isinstance(value, float):
                value = str(value)
            yield encoder(self.u(value))
            yield encoder('\r\n')
        for (key, filename, content) in files:
            key = self.u(key)
            filename = self.u(filename)
            yield encoder('--{}\r\n'.format(self.boundary))
            yield encoder(self.u('Content-Disposition: form-data; name="{}"; filename="{}"\r\n').format(key, filename))
            yield encoder('Content-Type: {}\r\n'.format(mimetypes.guess_type(filename)[0] or 'application/octet-stream'))
            yield encoder('\r\n')
            yield (content, len(content))
            yield encoder('\r\n')
        yield encoder('--{}--\r\n'.format(self.boundary))

    def encode(self, fields, files):
        body = io.BytesIO()
        for chunk, chunk_len in self.iter(fields, files):
            body.write(chunk)
        return self.content_type, body.getvalue()


class Caldera():

    def __init__(self, api_key, caldera_url="http://127.0.0.1:8888", debug=False, print_banner=True):

        self.PRINT_DEBUG = debug
        self.API_KEY = api_key

        self.caldera_URL = caldera_url

        self.AGENTS_ENDPOINT = self.caldera_URL + "/api/v2/agents"
        self.SERVER_HEALTH_ENDPOINT = self.caldera_URL + "/api/v2/health"
        self.ABILITIES_ENDPOINT = self.caldera_URL + "/api/v2/abilities"
        self.ADVERSARY_PROFILES_ENDPOINT = self.caldera_URL + "/api/v2/adversaries"
        self.OPERATIONS_ENDPOINT = self.caldera_URL + "/api/v2/operations"
        self.PLUGINS_ENDPOINT = self.caldera_URL + "/api/v2/plugins"
        self.ACCESS_EXPLOIT_ENDPOINT = self.caldera_URL + "/plugin/access/exploit"
        self.LINK_RESULT_ENDPOINT = self.caldera_URL + "/api/rest"
        self.FILES_UPLOAD_ENDPOINT = self.caldera_URL + "/file/upload"

        if print_banner: self._print_banner()

        if self.PRINT_DEBUG:
            print("Initialising Caldera API library")
            print(f"URL: {self.caldera_URL}")

        if not self.API_KEY:
            print("\n[!] API key required for usage!\n")
            exit()

    def _print_banner(self):
        print("""
                          ###                           
                       #######                          
                 ### ### #######                        
                ######  ##############                  
               ##  ###  ##########   ##                 
              ### ###############    ####               
            ####################### ######              
           #################################            
          ####################################          
        #######################################         MITRE Caldera
       ##########################################           Python API
     ##############################################     
    ################################################    
   ##################################################   
                                                        
 ######   ####   ##     ######   ###### ######    ####  
###      ##  ##  ##     ##  ###  ##     ##  ###  ##  ## 
###      ######  ##     ##  ###  ##     ######   #######
 ######  ##  ##  #####  ######   ###### ###  ### ###  ###
        """) 

    def _error_message(self, message):
        return { "error": str(message) }

    def _status_message(self, message):
        return { "status": str(message) } 

    def _parse_ability_yaml(self, data):
        executors = []
        for platform in data['platforms']:
            for executor in list(data['platforms'][platform].keys()):
                if executor != "vars":
                    executors.append({
                        "name": executor,
                        "platform": platform,
                        "command": data['platforms'][platform][executor]['command'],
                        "payloads": data['platforms'][platform][executor]['payloads'],
                        "parsers": [],
                        "cleanup": []
                    })
        caldera_json = {
            "ability_id": data['id'],
            "name": data['name'],
            "access": {},
            "additional_info": {},
            "buckets": [],
            "cleanup": [],
            "tactic": data['tactic'],
            "technique_id": data['technique']['attack_id'],
            "technique_name": data['technique']['name'],
            "description": data['description'],
            "executors": executors,
            "privilege": "",
            "repeatable": True,
            "requirements": [],
            "singleton": True
        }
        return caldera_json


    def _generate_agents_table(self, data, print_table=True):
        x = pt()
        x.field_names = ["Paw", "Name", "Platform", "Protocol", "Executors", "Group", "Last Seen"]            
        for agent in data:
            x.add_row([agent['paw'], agent['host'], agent['platform'], agent['contact'], ", ".join(agent['executors']), agent['group'], agent['last_seen']])
        if print_table: print(x)
        return x
    

    def _generate_agents_attribute_table(self, data, print_table=True):
        x = pt()
        x.field_names = ["Paw", "Group", "Trusted", "Sleep Min.", "Sleep Max.", "Watchdog", "Pending Contact"]            
        for agent in data:
            x.add_row([
                agent['paw'], 
                agent['group'],
                agent['trusted'],
                agent['sleep_min'],
                agent['sleep_max'],
                agent['watchdog'],
                agent['pending_contact']
            ])
        if print_table: print(x)
        return x
    

    def _generate_plugin_table(self, data, print_table=True):
        x = pt()
        x.field_names = ["Plugin Name", "Description", "Enabled"] 
        x.align['Description'] = 'l'           
        for plugin in data:
            x.add_row([
                plugin['name'], 
                plugin['description'],
                plugin['enabled']
            ])
        if print_table: print(x)
        return x
    

    def _generate_adversaries_table(self, data, print_table=True):
        x = pt()
        x.field_names = ["ID", "Name", "Description", "Objective", "Abilities", "Tags"]           
        x.align['Description'] = 'l'           
        for ap in data:
            wrapped_description = wrap(str(ap['description']) or '', VAL_WRAP_WIDTH) or ['']
            wrapped_name = wrap(str(ap['name']) or '', VAL_WRAP_WIDTH) or ['']

            x.add_row([
                ap['adversary_id'], 
                wrapped_name[0],
                wrapped_description[0],
                ap['objective'],
                ap['atomic_ordering'],
                ap['tags']
            ])
            if not(len(wrapped_description) <= 1 and len(wrapped_name) <= 1):
                for i in range(1,max(len(wrapped_description), len(wrapped_name))):
                    name_line = ""
                    desc_line = ""
                    
                    try: name_line = wrapped_name[i]
                    except: pass
                    
                    try: desc_line = wrapped_description[i]
                    except: pass

                    x.add_row(['',name_line,desc_line,'','',''])

        if print_table: print(x)
        return x

    def _generate_operations_table(self, data, print_table=True):
        x = pt()
        x.field_names = ["ID", "Name", "Hosts", "Start Time", "State"]           
        for op in data:
            x.add_row([
                op['id'], 
                op['name'],
                ', '.join([host['paw'] for host in op['host_group']]),
                op['start'],
                op['state']
            ])
        if print_table: print(x)
        return x
    

    def _generate_abilities_table(self, data, print_table=True):
        x = pt()
        x.field_names = ["ID", "Name", "Tactic", "Technique", "Executors", "Platforms", "Description"] 
        x.align['Description'] = 'l'           
        for ability in data:
            wrapped_description = wrap(str(ability['description']) or '', VAL_WRAP_WIDTH) or ['']
            wrapped_name = wrap(str(ability['name']) or '', VAL_WRAP_WIDTH) or ['']

            x.add_row([
                ability['ability_id'], 
                wrapped_name[0], 
                ability['tactic'],
                f"{ability['technique_id']}",
                ", ".join(set([exc['name'] for exc in ability['executors']])),
                ", ".join(set([exc['platform'] for exc in ability['executors']])),
                wrapped_description[0],
            ])
            if not(len(wrapped_description) <= 1 and len(wrapped_name) <= 1):
                for i in range(1,max(len(wrapped_description), len(wrapped_name))):
                    name_line = ""
                    desc_line = ""
                    
                    try: name_line = wrapped_name[i]
                    except: pass
                    
                    try: desc_line = wrapped_description[i]
                    except: pass

                    x.add_row(['',name_line,'','','','',desc_line])
 
        if print_table: print(x)
        return x
    
    
    def _generate_links_table(self, data, print_table=True):
        x = pt()
        x.field_names = ["Link ID", "Name", "Tactic", "Technique", "Execution Time", "Executor", "Output"] 
        for link in data:
            wrapped_name = wrap(str(link['ability']['name']) or '', VAL_WRAP_WIDTH) or ['']
            output = link.get('output', '')
            if output:
                try:
                    output = b64decode(output).decode()
                except:
                    output = "(Failed B64 Decode) " + output
            x.add_row([
                link['id'], 
                wrapped_name[0], 
                link['ability']['tactic'],
                f"{link['ability']['technique_id']}",
                link['agent_reported_time'],
                link['executor']['name'],
                output
            ])
            for name_line in wrapped_name[1:]:
                x.add_row(['',name_line,'','','','', ''])

        if print_table: print(x)
        return x


    def _make_web_request(self, url, body=None, params={}, method="", file_upload=None, extra_headers={}, auth=True):

        try:
            params = urllib.parse.urlencode(params)

            headers = {}
            if auth:
                headers["KEY"] = self.API_KEY
            
            if extra_headers:
                for header in extra_headers:
                    headers[header] = extra_headers[header]
                
            request = {
                "headers": headers,
                "url": url + "?" + params if params else url
            }

            if body:
                headers["Content-Type"] = "application/json"
                request['data'] = json.dumps(body).encode()
            
            elif file_upload:
                files = [('upload',file_upload[0],file_upload[1])]
                content_type, body = MultipartFormdataEncoder().encode([], files)
                headers["Content-Type"] = content_type
                headers["Content-Length"] = len(body)
                request['data'] = body

            if method: request['method'] = method

            req = urllib.request.Request(**request)

            with urllib.request.urlopen(req) as f:
                data = f.read()
            try:
                return json.loads(data)
            except:
                return { "response": str(data.decode()) }

        except Exception as e:
            return self._error_message(e)
        
    '''
    Server Health
    '''
    def get_server_health(self):
        data = self._make_web_request(self.SERVER_HEALTH_ENDPOINT)
        if self.PRINT_DEBUG:
            print(f"{data['application']} {data['version']}\n")
            print("Plugins:")
            self._generate_plugin_table(data['plugins'])
        return data
    
    '''
    Operations
    '''
    def get_operations(self, sort=None, include=[], exclude=[], id=None, print_table=True):
        params = {}
        if include:
            params["include"] = include
        if exclude:
            params["exclude"] = exclude
        if sort:
            params["sort"] = sort

        base_url = f"{self.OPERATIONS_ENDPOINT}"
        if id: 
            base_url+= f"/{id}"
        
        url = f"{base_url}?{urlencode(params, doseq=True)}"

        if self.PRINT_DEBUG: print(f"URL: {url}")

        data = self._make_web_request(url)

        if not isinstance(data, list):
            data = [data]
        
        if self.PRINT_DEBUG: 
            if print_table:
                self._generate_operations_table(data)
        
        return data

    def add_operation(self, 
        name, 
        adversary_id,
        group='',
        autonomous=1,    
        auto_close=False,
        jitter_min=2,
        jitter_max=8,
        state="running",
        visibility=51,
        obfuscator="plain-text",
        source="ed32b9c3-9593-4c33-b0db-e2007315096b",
        planner="aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a",
    ):
        data = {
            "name": name,
            "autonomous":autonomous,
            # "use_learning_parsers":True,
            "auto_close":auto_close,
            "jitter":f"{jitter_min}/{jitter_max}",
            "state":state,
            "visibility":visibility,
            "obfuscator":obfuscator,
            "source": {
                "id": source
            },
            "planner": {
                "id": planner
            },
            "adversary":{
                "adversary_id":adversary_id
            },
            "group":group
        }

        if self.PRINT_DEBUG:
            print(f"URL: {self.OPERATIONS_ENDPOINT}")

        data = self._make_web_request(self.OPERATIONS_ENDPOINT, method='POST', body=data)
        return data


    '''
    Agents
    '''

    def get_agents(self, sort=None, include=[], exclude=[], paw=None, print_table=True):
        params = {}
        if include:
            params["include"] = include
        if exclude:
            params["exclude"] = exclude
        if sort:
            params["sort"] = sort

        base_url = f"{self.AGENTS_ENDPOINT}"
        if paw: 
            base_url+= f"/{paw}"
        
        url = f"{base_url}?{urlencode(params, doseq=True)}"

        if self.PRINT_DEBUG: print(f"URL: {url}")

        data = self._make_web_request(url)

        if not isinstance(data, list):
            data = [data]
        
        if self.PRINT_DEBUG: 
            if print_table:
                self._generate_agents_table(data)
        
        return data


    def get_agent(self, name=None, paw=None):
        if name and paw: 
            return self._error_message("Cannot fetch agent by name and paw, use one.")
        
        if name:
            all_agents = self.get_agents(print_table=False)
            data = [agent for agent in all_agents if name.lower() in agent['host'].lower()]
            if self.PRINT_DEBUG: self._generate_agents_table(data)
        elif paw:
            data = self.get_agents(paw=paw)
    
        if not isinstance(data, list): 
            data = [data]
        
        return data
    

    def get_executions_for_agent(self, paw, fetch_output=False):
        data = self.get_agents(paw=paw, print_table=False)
        links = data[0]['links']
        
        if fetch_output:
            for link in links:
                link_id = link['id']
                result = self.get_result_for_link_execution(link_id)
                output = result['output']
                link['output'] = output
        
        if self.PRINT_DEBUG:
            self._generate_links_table(links)
    
        return links


    def get_result_for_link_execution(self, id):
        link_data = {
            "index": "result",
            "link_id": id
        }
        data = self._make_web_request(self.LINK_RESULT_ENDPOINT, body=link_data, method='POST')
        return data


    def update_agent_attribute(self, paw, group=None, trusted=None, sleep_min=None, sleep_max=None, watchdog=None, pending_contact=None):
        updates = {}
        if group != None:             updates['group'] = group 
        if trusted != None:           updates['trusted'] = trusted 
        if sleep_min != None:         updates['sleep_min'] = sleep_min 
        if sleep_max != None:         updates['sleep_max'] = sleep_max 
        if watchdog != None:          updates['watchdog'] = watchdog 
        if pending_contact != None:   updates['pending_contact'] = pending_contact

        data = self._make_web_request(f"{self.AGENTS_ENDPOINT}/{paw}", body=updates, method="PATCH")
        
        if self.PRINT_DEBUG: self._generate_agents_attribute_table([data])
        return data
    
    '''
    Abilities
    '''

    def get_abilities(self, sort=None, include=[], exclude=[], id=None, print_table=True):
        params = {}
        if include:
            params["include"] = include
        if exclude:
            params["exclude"] = exclude
        if sort:
            params["sort"] = sort

        base_url = f"{self.ABILITIES_ENDPOINT}"
        if id: 
            base_url+= f"/{id}"
        
        url = f"{base_url}?{urlencode(params, doseq=True)}"

        if self.PRINT_DEBUG: print(f"URL: {url}")

        data = self._make_web_request(url)

        if not isinstance(data, list):
            data = [data]
        
        if self.PRINT_DEBUG: 
            if print_table:
                self._generate_abilities_table(data)
        
        return data


    def get_ability(self, name=None, id=None):
        if name and id: 
            return self._error_message("Cannot fetch ability by name and id, use one.")
        
        if name:
            all_abilities = self.get_abilities(print_table=False)
            data = [ability for ability in all_abilities if name.lower() in ability['name'].lower()]
            if self.PRINT_DEBUG: self._generate_abilities_table(data)
        elif id:
            data = self.get_abilities(id=id)
    
        if not isinstance(data, list): 
            data = [data]
        
        return data
    
    def add_ability(self, ability_json, skip_conversion=False):
        if not skip_conversion:
            ability_json = self._parse_ability_yaml(ability_json)
        
        url = f"{self.ABILITIES_ENDPOINT}/{ability_json['ability_id']}"
        if self.PRINT_DEBUG:
            print(f"URL: {url}")
        

        data = self._make_web_request(url, method='PUT', body=ability_json)    
        return data
    
    '''
    Adversary Profiles
    '''
    def get_adversary_profiles(self, id=None, print_table=True):

        data = self._make_web_request(f"{self.ADVERSARY_PROFILES_ENDPOINT}{'/'+ id if id else ''}")
        
        if not isinstance(data, list):
            data = [data]
        
        if self.PRINT_DEBUG: 
            if print_table:
                self._generate_adversaries_table(data)
        return data


    def add_adversary_profile(self,
            name, 
            description="---",
            atomic_ordering=[],
            objective="495a9828-cab1-44dd-a0ca-66e58177d8cc",
            tags=[],
            has_repeatable_abilities=False,
            plugin=""
        ):
        
        data = {
            "adversary_id": str(uuid4()),
            "name": name,
            "description": description,
            "atomic_ordering": atomic_ordering,
            "objective": objective,
            "tags": tags,
            "has_repeatable_abilities": has_repeatable_abilities,
            "plugin": plugin
        }
        output = self._make_web_request(f"{self.ADVERSARY_PROFILES_ENDPOINT}", method='POST', body=data)
        return output


    '''
    Plugins
    '''

    def get_plugins(self, include=[], exclude=[], name=None):

        data = self._make_web_request(f"{self.PLUGINS_ENDPOINT}{'/'+ name if name else ''}?include{str(include)}&exclude{str(exclude)}")
        
        if not isinstance(data, list):
            data = [data]
        
        if self.PRINT_DEBUG: self._generate_plugin_table(data)
        return data

    def execute_ability_on_agent(self, paw, ability_id, facts=[], obfuscator="plain-text"):
        execution = {
            "paw": paw, 
            "ability_id": ability_id, 
            "facts": [], 
            "obfuscator": obfuscator
        }

        data = self._make_web_request(f"{self.ACCESS_EXPLOIT_ENDPOINT}", body=execution, method='POST')

        if self.PRINT_DEBUG:
            print(f"Outcome: {data}")

        return self._status_message(data)
    
    '''
    Files
    '''
    def add_file(self, content, file_name, agent):
        if self.PRINT_DEBUG: print(f"URL: {self.FILES_UPLOAD_ENDPOINT}")

        extra_headers = {
            "X-Request-Id": agent['paw']
        }

        data = self._make_web_request(self.FILES_UPLOAD_ENDPOINT, file_upload=(file_name, content), method='POST', extra_headers=extra_headers, auth=False)

        return data