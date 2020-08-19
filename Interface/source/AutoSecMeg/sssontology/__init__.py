from rdflib import RDFS, RDF, Namespace, Graph, URIRef, Literal, XSD
import rdflib
import json
from SPARQLWrapper import SPARQLWrapper, JSON, POST, DIGEST, BASIC

class sssontology(object):
    def __init__(self,filename=None, jena_address=None):
        assert not (filename is None and jena_address is None)
        if jena_address is not None:
            self.jena_address = jena_address
            self.jenamode = True
            self.g = Graph()
            self.ssso = Namespace('http://www.semanticweb.org/linch/ontologies/2018/11/ssso#')
            self.g.bind('ssso', self.ssso)
            self.g.bind('rdf', RDF)
            self.g.bind('xsd', XSD)
            self.m = {
                'http://www.w3.org/1999/02/22-rdf-syntax-ns': 'rdf',
                'http://www.semanticweb.org/linch/ontologies/2018/11/ssso':'ssso'
                }
        elif filename is not None:
            self.filename=filename
            self.jenamode = False
            self.g = Graph()
            self.g.parse(self.filename, format='turtle')
            self.ssso = Namespace('http://www.semanticweb.org/linch/ontologies/2018/11/ssso#')
            self.g.bind('ssso', self.ssso)
            self.g.bind('rdf', RDF)
            self.g.bind('xsd', XSD)
            self.m = {
                'http://www.w3.org/1999/02/22-rdf-syntax-ns': 'rdf',
                'http://www.semanticweb.org/linch/ontologies/2018/11/ssso':'ssso'
                }

    def jena2rdflib(self, dic):
        type_name = dic['type']
        datatype = dic.get('datatype')
        value = dic['value']
        if type_name == 'bnode':
            return rdflib.term.BNode(value)
        elif type_name == 'uri':
            return rdflib.term.URIRef(value)
        elif type_name == 'literal':
            return rdflib.term.Literal(value, datatype=datatype)
        else:
            return None

    def jena_convertor(self, res_dic):
        variables = res_dic.get('head', {}).get('vars', [])
        if variables == [] and res_dic.get('boolean') is not None:
            return res_dic.get('boolean') # ASK
        bindings = res_dic.get('results', {}).get('bindings', [])
        ans = []
        for item in bindings:
            res = []
            for var in variables:
                if item.get(var) is None:
                    res.append(None)
                    continue
                res.append(self.jena2rdflib(item.get(var)))
            ans.append(tuple(res))
        return ans

    def refresh(self):
        self.g = Graph()
        self.g.parse(self.filename, format='turtle')
    def commit(self):
        self.g.serialize(destination=self.filename, format='turtle')

    def add(self, triple):
        self.g.add(triple)
        self.g.serialize(destination=self.filename, format='turtle')

    def bulk_insert(self, triples):
        """
        Bulk insert triples using SPARQL INSERT
        :param triples: list of triples
        :return: None
        """
        def literal_handler(literal):
            datatype = literal.datatype.toPython() if literal.datatype is not None else None
            if datatype is None:
                return f'"{str(literal)}"'
            if datatype == 'http://www.w3.org/2001/XMLSchema#integer':
                return f'"{str(literal)}"^^xsd:integer'
            elif datatype == 'http://www.w3.org/2001/XMLSchema#float':
                return f'"{str(literal)}"^^xsd:float'
            elif datatype == 'http://www.w3.org/2001/XMLSchema#double':
                return f'"{str(literal)}"^^xsd:double'
            elif datatype == 'http://www.w3.org/2001/XMLSchema#decimal':
                return f'"{str(literal)}"^^xsd:decimal'
            elif datatype == 'http://www.w3.org/2001/XMLSchema#boolean':
                return f'"{str(literal)}"^^xsd:boolean'
            elif datatype == 'http://www.w3.org/2001/XMLSchema#dateTime':
                return f'"{str(literal)}"^^xsd:dateTime'
            elif datatype == 'http://www.w3.org/2001/XMLSchema#string':
                return f'"{str(literal)}"^^xsd:string'
            else:
                return f'"{str(literal)}"'

        insert_q = """
        INSERT DATA
        {
        
        """
        for triple in triples:
            triple=[f"<{item.toPython()}>" if type(item) is not Literal else literal_handler(item) for item in triple]
            insert_q+=f"{triple[0]} {triple[1]} {triple[2]}.\n"
        insert_q+="}"
        self.update(insert_q)


    def bulk_add(self, triples):
        """
        :param triples: list of triples
        :return: None
        """
        for triple in triples:
            self.g.add(triple)
        self.g.serialize(destination=self.filename, format='turtle')
    def bulk_remove(self, triples):
        """
        :param triples: list of triples
        :return: None
        """
        for triple in triples:
            self.g.remove(triple)
        self.g.serialize(destination=self.filename, format='turtle')
    def remove(self,triple):
        self.g.remove(triple)
        self.g.serialize(destination=self.filename, format='turtle')

    def query(self,q,fullURI=False):
        if self.jenamode:
            rows = self.jena_query(q=q)
            if type(rows) is bool:
                return rows  # ASK
        else:
            rows = self.g.query(q)
            try:
                if rows.type=='ASK':
                    return rows.askAnswer
            except:
                pass
        if not fullURI:
            rows = [[self.m[r.split('#')[0]] + ':' + r.split('#')[1] if isinstance(r, URIRef) and '#' in r else r for r in row] for row in rows]
            return rows
        return list(rows)

    def update(self, q):
        if self.jenamode:
            self.jena_update(q=q)
        else:
            self.g.update(q)
            self.g.serialize(destination=self.filename, format='turtle')

    def jena_query(self, q):
        QEngine = SPARQLWrapper(self.jena_address+'/sparql')
        QEngine.setQuery(f"""
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
            PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
            PREFIX ssso: <http://www.semanticweb.org/linch/ontologies/2018/11/ssso#>
            {q}
        """)
        QEngine.setReturnFormat(JSON)
        res = QEngine.query().convert()
        converted_res = self.jena_convertor(res)
        return converted_res

    def jena_update(self, q):
        QEngine = SPARQLWrapper(self.jena_address+'/update')
        QEngine.setHTTPAuth(BASIC)
        QEngine.setCredentials("admin", "password")
        QEngine.setMethod(POST)
        QEngine.setQuery(f"""
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
            PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
            PREFIX ssso: <http://www.semanticweb.org/linch/ontologies/2018/11/ssso#>
            {q}
        """)
        QEngine.query()

    def query_data(self,object,dataproperty='hasData',object_class=None,fullURI=False):
        """
        Query the value of a data property assertion of an object
        :param q: string
        :return: [data]
        """
        if object_class is None:
            q = f"""
            select ?data where {{
            ssso:{object} ssso:{dataproperty} ?data.
            }}
            """
        else:
            q = f"""
            select ?data where {{
            ssso:{object} rdf:type ssso:{object_class}.
            ssso:{object} ssso:{dataproperty} ?data.
            }}
            """
        res = self.query(q)
        res = [[item.toPython() for item in li] for li in res]
        return res

    def exists(self, object):
        """
        Check if the object exists
        :param object: string
        :return: boolean
        """
        q = f"""
        ASK WHERE {{
        {{ssso:{object} ?p ?o . }}
        UNION
        {{?s ?p ssso:{object} . }}
        }}
        """
        rows = self.query(q)
        return rows

    def ask(self, q):
        rows = self.g.query(q)
        return [row for row in rows][0]

    def get_top_class(self, uri):
        """
        Return the top class of an instance
        :param uri: URI String
        :return: URI String
        """
        q = f"""
            SELECT ?topclass
            WHERE
            {{
            ssso:{uri} rdf:type ?class.
            ?class rdfs:subClassOf ?topclass.
            }}
            """
        try:
            return self.query(q)[0][0].split(':')[-1]
        except:
            return None

    def get_class(self, uri):
        """
        Return the top class of an instance
        :param uri: URI String
        :return: URI String
        """
        q = f"""
            SELECT ?class
            WHERE
            {{
            ssso:{uri} rdf:type ?class.
            }}
            """
        try:
            return self.query(q)[0][0].split(':')[-1]
        except:
            return None

    def get_user_trust_level(self, uri):
        """
        Return the trust level a user
        :param uri: User URI String
        :return: Trust Level Integer
        """
        q = f"""
            SELECT ?sl
            WHERE
            {{
            ssso:{uri} ssso:hasPolicy ?sl.
            ?sl rdf:type ssso:Security_Level.
            }}
            """
        try:
            return int(self.query(q)[0][0].split(':')[-1][-1])
        except:
            return None

    def get_env_security_level_and_classification_level(self, uri):
        """
        Return the security level a location/group. If there are multiple results (e.g. an equipment belongs to a group and a location simultaneously), return the minimal security level.
        :param uri: service/equipment/location/group URI String
        :return: Trust Level Integer
        """
        def get_max_classification_level(li):
            if 'Classified' in li:
                return 'Classified'
            elif 'Normal' in li and 'Classified' not in li:
                return 'Normal'
            elif 'Public' in li and 'Classified' not in li and 'Normal' not in li:
                return 'Public'

        q = f"""
            SELECT ?sl ?cl
            WHERE
            {{
                OPTIONAL 
                    {{
                        ?sl rdf:type ssso:Security_Level.
                        ?cl rdf:type ssso:Classification_Level.
                        BIND (ssso:{uri} AS ?svc).
                        ?svc rdf:type ?svcclass.
                        ?svcclass rdfs:subClassOf ?topclass.
                        ?topclass rdfs:subClassOf ssso:Service.
                        ?eq ssso:hasService ?svc.
                        ?eq ssso:hasContext ?loc.
                        {{?loc rdf:type ssso:Location.}}
                        ?loc ssso:hasPolicy ?sl.
                        ?loc ssso:hasPolicy ?cl.
                    }}.
                OPTIONAL 
                    {{
                        ?sl rdf:type ssso:Security_Level.
                        BIND (ssso:Classified AS ?cl).
                        BIND (ssso:{uri} AS ?svc).
                        ?svc rdf:type ?svcclass.
                        ?svcclass rdfs:subClassOf ?topclass.
                        ?topclass rdfs:subClassOf ssso:Service.
                        ?eq ssso:hasService ?svc.
                        ?eq ssso:hasContext ?loc.
                        {{?loc rdf:type ssso:Group.}}.
                        ?loc ssso:hasPolicy ?sl.
                    }}.
                OPTIONAL 
                    {{
                        ?sl rdf:type ssso:Security_Level.
                        ?cl rdf:type ssso:Classification_Level.
                        BIND (ssso:{uri} AS ?eq).
                        ?eq rdf:type ?svcclass.
                        ?svcclass rdfs:subClassOf ?topclass.
                        ?topclass rdfs:subClassOf ssso:Equipment.
                        ?eq ssso:hasContext ?loc.
                        {{?loc rdf:type ssso:Location.}}
                        ?loc ssso:hasPolicy ?sl.
                        ?loc ssso:hasPolicy ?cl.
                    }}.
                OPTIONAL 
                    {{
                        ?sl rdf:type ssso:Security_Level.
                        BIND (ssso:Classified AS ?cl).
                        BIND (ssso:{uri} AS ?eq).
                        ?eq rdf:type ?svcclass.
                        ?svcclass rdfs:subClassOf ?topclass.
                        ?topclass rdfs:subClassOf ssso:Equipment.
                        ?eq ssso:hasContext ?loc.
                        {{?loc rdf:type ssso:Group.}}.
                        ?loc ssso:hasPolicy ?sl.
                    }}.
                OPTIONAL 
                    {{
                        ?cl rdf:type ssso:Classification_Level.
                        ?sl rdf:type ssso:Security_Level.
                        BIND (ssso:{uri} AS ?loc).
                        {{?loc rdf:type ssso:Location.}}
                        ?loc ssso:hasPolicy ?sl.
                        ?loc ssso:hasPolicy ?cl.
                    }}.
                OPTIONAL 
                    {{
                        BIND (ssso:Classified AS ?cl).
                        ?sl rdf:type ssso:Security_Level.
                        BIND (ssso:{uri} AS ?loc).
                        {{?loc rdf:type ssso:Group.}}
                        ?loc ssso:hasPolicy ?sl.
                    }}.
            }}
            """
        res = self.query(q)
        try:
            return (min([int(item[0][-1]) for item in res]), get_max_classification_level([item[1].split(':')[-1] for item in res]))
        except:
            return None

    def get_required_SLAP(self, uri):
        """
        Return the required security level or access policy of a service uri
        :param uri: Service URI String
        :return: URI String
        """
        q = f"""
            SELECT ?sl ?class
            WHERE
            {{
            OPTIONAL 
                {{ssso:{uri} ssso:hasPolicy ?sl.
                ?sl rdf:type ssso:Access_Policy.
                BIND ("Access_Policy" AS ?class).}}.
            OPTIONAL 
                {{ssso:{uri} ssso:hasPolicy ?sl.
                ?sl rdf:type ssso:Security_Assessment_Policy.
                BIND ("Security_Assessment_Policy" AS ?class).}}.
            OPTIONAL 
                {{ssso:{uri} ssso:hasPolicy ?sl.
                ?sl rdf:type ssso:Security_Level.
                BIND ("Security_Level" AS ?class).}}.
            }}
        """
        try:
            return self.query(q)
        except:
            return None

    def get_required_SLTLAP(self, uri):
        """
        Return the provided trust level or turst level assessment policy of an authentication service uri
        :param uri: Auth Service URI String
        :return: URI String List
        """
        q = f"""
            SELECT ?sl ?class
            WHERE
            {{
            OPTIONAL 
                {{ssso:{uri} ssso:hasPolicy ?sl.
                ?sl rdf:type ssso:Trust_Level_Assessment_Policy.
                BIND ("Trust_Level_Assessment_Policy" AS ?class).}}.
            OPTIONAL 
                {{ssso:{uri} ssso:hasPolicy ?sl.
                ?sl rdf:type ssso:Security_Level.
                BIND ("Trust_Level" AS ?class).}}.
            }}
        """
        try:
            return self.query(q)
        except:
            return None

    def get_required_SLTrustLAP(self, uri):
        """
        Return the provided trust level or trust level assessment policy of an authentication service
        :param uri: Auth Service URI String
        :return: URI String List
        """
        q = f"""
            SELECT ?sl ?class
            WHERE
            {{
            OPTIONAL 
                {{ssso:{uri} ssso:hasPolicy ?sl.
                ?sl rdf:type ssso:Trust_Level_Assessment_Policy.
                BIND ("Trust_Level_Assessment_Policy" AS ?class).}}.
            OPTIONAL 
                {{ssso:{uri} ssso:hasPolicy ?sl.
                ?sl rdf:type ssso:Security_Level.
                BIND ("Trust_Level" AS ?class).}}.
            }}
        """
        try:
            return self.query(q)
        except:
            return None

    def get_endpoint_list(self, endpoint_sparql, userUUID, serviceUUID):
        """
        Return the list of endpoint URI
        :param endpoint_sparql: Endpoint SPARQL
        :param userUUID: Requester user UUID
        :param serviceUUID: Requested service UUID
        :return: URI String List
        """
        q = f"""
            SELECT ?Endpoint
            {{
                BIND (ssso:{userUUID} AS ?User).
                BIND (ssso:{serviceUUID} AS ?Service).
                ?Endpoint rdf:type ?class.
                ?class rdfs:subClassOf ssso:Communication_Endpoint.
                {endpoint_sparql}
            }}
            """
        try:
            return [item[0].split(':')[-1] for item in self.query(q)]
        except:
            return None

    def get_endpoint_list_TAP(self, endpoint_sparql, equipmentUUID, envUUID):
        """
        Return the list of endpoint URI (for evaluating threat assessment policy only)
        :param endpoint_sparql: Endpoint SPARQL
        :param equipmentUUID: Equipment UUID
        :param envUUID: Threat Location/Group UUID
        :return: URI String List
        """
        q = f"""
            SELECT ?Endpoint
            {{
                BIND (ssso:{equipmentUUID} AS ?Equipment).
                BIND (ssso:{envUUID} AS ?Location).
                ?Endpoint rdf:type ?class.
                ?class rdfs:subClassOf ssso:Communication_Endpoint.
                {endpoint_sparql}
            }}
            """
        try:
            return [item[0].split(':')[-1] for item in self.query(q)]
        except:
            return None

    def query_endpoint(self, uri):
        """
        Return the protocol, address, and request model of an endpoint instance
        :param uri: Endpoint URI
        :return: (Protocol, Address, Request model json)
        """
        q = f"""
            SELECT ?protc ?addr ?reqmdata
            {{
                BIND (ssso:{uri} AS ?edpt).
                ?edpt rdf:type ?protc.
                ?protc rdfs:subClassOf ssso:Communication_Endpoint.
                ?edpt ssso:hasData ?addr.
                OPTIONAL
                    {{  ?edpt ssso:hasContext ?reqm.
                        ?reqm rdf:type ssso:Request_Model.
                        ?reqm ssso:hasData ?reqmdata.}}.
            }}
            """

        try:
            res = self.query(q)
            protocol = res[0][0].split(':')[-1]
            address = res[0][1].toPython()
            reqest_model = json.loads(res[0][2]) if res[0][2] is not None else None
            res = (protocol, address, reqest_model)
            return res
        except:
            return None

    def evaluate_Access_Policy(self, policy, userUUID, serviceUUID):
        """
        Evaluate an Access Policy
        :param policy: Access Policy (not URI)
        :param userUUID: Requester UUID
        :param serviceUUID: Service UUID
        :return: True or False
        """
        q = f"""
            ASK WHERE
            {{
                BIND (ssso:{userUUID} AS ?User).
                BIND (ssso:{serviceUUID} AS ?Service).
                {policy}
            }}
            """
        return self.query(q)

    def evaluate_Trust_Level_Assessment_Policy(self, policy, userUUID, serviceUUID):
        """
        Evaluate a Trust Level Assessment Policy
        :param policy: Trust Policy (not URI)
        :param userUUID: Requester UUID
        :param serviceUUID: Service UUID
        :return: Provided Trust Level
        """
        q = f"""
            SELECT ?Trust_Level
            {{
                BIND (ssso:{userUUID} AS ?User).
                BIND (ssso:{serviceUUID} AS ?Service).
                {policy}
            }}
            """
        res = self.query(q)
        try:
            return res[0][0].split(':')[-1]
        except:
            return None

    def evaluate_Security_Level_Assessment_Policy(self, policy, userUUID, serviceUUID):
        """
        Evaluate a Security Assessment Policy
        :param policy: Security Policy (not URI)
        :param userUUID: Requester UUID
        :param serviceUUID: Service UUID
        :return: Required Security Level
        """
        q = f"""
            SELECT ?Security_Level
            {{
                BIND (ssso:{userUUID} AS ?User).
                BIND (ssso:{serviceUUID} AS ?Service).
                {policy}
            }}
            """
        res = self.query(q)
        try:
            return res[0][0].split(':')[-1]
        except:
            return None

    def evaluate_Threat_Assessment_Policy(self, policy,  equipmentUUID, Threat_Class, envUUID):
        """
        Evaluate a Threat Assessment Policy
        :param policy: Threat Policy (not URI)
        :param equipmentUUID: The UUID of the equipment that reports the threat
        :param Threat_Class: The class the threat belongs to
        :param envUUID: An optional parameter representing the location/group the threat is in.
        :return: Posed Threat Level
        """
        if envUUID is None:
            q = f"""
                SELECT ?Threat_Level
                {{
                    BIND (ssso:{equipmentUUID} AS ?Equipment).
                    BIND (ssso:{Threat_Class} AS ?Threat_Class).
                    {policy}
                }}
                """
        else:
            q = f"""
                SELECT ?Threat_Level
                {{
                    BIND (ssso:{equipmentUUID} AS ?Equipment).
                    BIND (ssso:{Threat_Class} AS ?Threat_Class).
                    BIND (ssso:{envUUID} AS ?Env).
                    {policy}
                }}
                """
        try:
            res = self.query(q)
            return res[0][0].split(':')[-1]
        except:
            return None

    def evaluate_Threat_Mitigation_Policy(self, policy,  equipmentUUID, Threat_Class, envUUID):
        """
        Evaluate a Threat Mitigation Policy
        """
        if envUUID is None:
            q = f"""
                SELECT ?Suspend ?Disable ?Enable ?Threat_Level
                {{
                    BIND (ssso:{equipmentUUID} AS ?Equipment).
                    BIND (ssso:{Threat_Class} AS ?Threat_Class).
                    {policy}
                }}
                """
        else:
            q = f"""
                SELECT ?Suspend ?Disable ?Enable ?Threat_Level
                {{
                    BIND (ssso:{equipmentUUID} AS ?Equipment).
                    BIND (ssso:{Threat_Class} AS ?Threat_Class).
                    BIND (ssso:{envUUID} AS ?Env).
                    {policy}
                }}
                """
        try:
            res = self.query(q)
            service_to_suspend = list(set([item[0] for item in res if item[0] is not None]))
            service_to_suspend = [item.split(':')[-1] for item in service_to_suspend]
            service_to_disable = list(set([item[1] for item in res if item[1] is not None]))
            service_to_disable = [item.split(':')[-1] for item in service_to_disable]
            service_to_enable = list(set([item[2] for item in res if item[2] is not None]))
            service_to_enable = [item.split(':')[-1] for item in service_to_enable]
            mitigated_threat_level = list(set([item[3] for item in res if item[3] is not None]))
            mitigated_threat_level = 4 if mitigated_threat_level == [] else int(mitigated_threat_level[0][-1])
            return (service_to_suspend, service_to_disable, service_to_enable, mitigated_threat_level)
        except:
            return None

    def get_or_add_object(self, object, object_class):
        """
        Add an object to a specific class if it does not exist, otherwise do nothing.
        :param object: object to be added
        :param object_class: class the object belongs to
        :return: object
        """
        if not self.exists(object):
            self.bulk_insert([(self.ssso[object], RDF.type, self.ssso[object_class])])
        return object

    def query_value(self, *args, **kwargs):
        self.refresh()
        return self.g.value(*args, **kwargs)

    def update_triple(self, s, p, o, oclass):
        q = f"""
            DELETE 
            {{
                ssso:{s} ?p ?o.

            }}
            INSERT
            {{
                ssso:{s} ssso:{p} ssso:{o}
            }}
            WHERE
            {{
                ssso:{s} ?p ?o.
                ?o rdf:type ssso:{oclass}.
            }}
            """
        self.update(q)

    def update_endpoint_value(self, endpoint, value):
        q = f"""
            DELETE 
            {{
                ssso:{endpoint} ssso:hasValue ?o.

            }}
            INSERT
            {{
                ssso:{endpoint} ssso:hasValue {value}.
            }}
            WHERE
            {{
                OPTIONAL{{ssso:{endpoint} ssso:hasValue ?o.}}
            }}
            """
        self.update(q)

    def update_data_literal(self, individualURI, data):
        q = f"""
            DELETE 
            {{
                ssso:{individualURI} ssso:hasData ?o.

            }}
            INSERT
            {{
                ssso:{individualURI} ssso:hasData "{data}".
            }}
            WHERE
            {{
                OPTIONAL{{ssso:{individualURI} ssso:hasData ?o.}}
            }}
            """
        self.update(q)

    def add_individual_context(self, individual, context):
        q = f"""
            INSERT DATA
            {{
                ssso:{individual} ssso:hasContext ssso:{context}.
            }}
            """
        self.update(q)

    def add_individual_policy(self, individual, policy):
        q = f"""
            INSERT DATA
            {{
                ssso:{individual} ssso:hasPolicy ssso:{policy}.
            }}
            """
        self.update(q)

    def remove_triple(self, subject, property, object):
        q = f"""
            DELETE DATA
            {{
                ssso:{subject} ssso:{property} ssso:{object}.

            }}
            """
        self.update(q)

    def update_service_value(self, endpoint, value):
        q = f"""
            DELETE 
            {{
                ssso:{endpoint} ssso:hasValue ?o.

            }}
            INSERT
            {{
                ssso:{endpoint} ssso:hasValue '{value}'.
            }}
            WHERE
            {{
                OPTIONAL{{ssso:{endpoint} ssso:hasValue ?o.}}
            }}
            """
        self.update(q)

    def delete_threat(self, threatUUID):
        q = f"""
            DELETE 
            {{
                ssso:{threatUUID} ?p ?o.

            }}
            WHERE
            {{
                ssso:{threatUUID} ?p ?o.
                ssso:{threatUUID} rdf:type ?class.
                ?class rdfs:subClassOf ssso:Threat.
            }}
            """
        self.update(q)

    def delete_policy(self, policyUUID):
        q = f"""
            DELETE 
            {{
                ssso:{policyUUID} ?p ?o.

            }}
            WHERE
            {{
                ssso:{policyUUID} ?p ?o.
                ssso:{policyUUID} rdf:type ?class.
                ?class rdfs:subClassOf ssso:Policy.
            }}
            """
        self.update(q)

    def update_user_trust_level(self, userUUID, TrustLevel):
        q = f"""
            DELETE 
            {{
                ssso:{userUUID} ssso:hasPolicy ?o.

            }}
            INSERT
            {{
                ssso:{userUUID} ssso:hasPolicy ssso:{TrustLevel}.
            }}
            WHERE
            {{
                OPTIONAL{{ssso:{userUUID} ssso:hasPolicy ?o.
                ?o rdf:type ssso:Security_Level.}}
            }}
            """
        self.update(q)

    def list_service_on_device(self, equipmentUUID):
        q = f"""
            SELECT ?svc ?class
            {{
                BIND (ssso:{equipmentUUID} AS ?Equipment).
                ?Equipment ssso:hasService ?svc.
                ?svc rdf:type ?class.
            }}
            """
        res = self.query(q)
        return res

    def update_env_security_level(self, envUUID, SLint):
        q = f"""
            DELETE 
            {{
                ssso:{envUUID} ssso:hasPolicy ?o.

            }}
            INSERT
            {{
                ssso:{envUUID} ssso:hasPolicy ssso:SL-{SLint}.
            }}
            WHERE
            {{
                OPTIONAL{{ssso:{envUUID} ssso:hasPolicy ?o.
                ?o rdf:type ssso:Security_Level.}}
            }}
            """
        self.update(q)

    def get_TLTAP(self, equipmentUUID, Threat_Class):
        """
        Return the threat level or threat assessment policy of a threat
        :param equipmentUUID: Equipment UUID
        :param Threat_Class: Threat Class
        :return: URI String list and class
        """
        q = f"""
            SELECT ?thlap ?class
            WHERE
            {{
                BIND (ssso:{equipmentUUID} AS ?Equipment).
                BIND (ssso:{Threat_Class} AS ?Threat_Class).
                ssso:{equipmentUUID} ssso:hasContext ?thmdl.
                ?thmdl rdf:type ssso:Threat_Model.
                ?thmdl ssso:hasClass '{Threat_Class}'.
            OPTIONAL 
                {{?thmdl ssso:hasPolicy ?thlap.
                ?thlap rdf:type ssso:Threat_Mitigation_Policy.
                BIND ("Threat_Mitigation_Policy" AS ?class).}}.
            OPTIONAL 
                {{?thmdl ssso:hasPolicy ?thlap.
                ?thlap rdf:type ssso:Threat_Assessment_Policy.
                BIND ("Threat_Assessment_Policy" AS ?class).}}.
            OPTIONAL 
                {{?thmdl ssso:hasPolicy ?thlap.
                ?thlap rdf:type ssso:Threat_Level.
                BIND ("Threat_Level" AS ?class).}}.
        }}
        """
        try:
            return self.query(q)
        except:
            return None

    def get_location(self, uri):
        """
        Return the location/group of a service/equipment/user
        :param uri: service/equipment/user URI String
        :return: Location URI
        """

        q = f"""
            SELECT ?loc
            WHERE
            {{
                OPTIONAL 
                    {{
                        BIND (ssso:{uri} AS ?svc).
                        ?svc rdf:type ?svcclass.
                        ?svcclass rdfs:subClassOf ?topclass.
                        ?topclass rdfs:subClassOf ssso:Service.
                        ?eq ssso:hasService ?svc.
                        ?eq ssso:hasContext ?loc.
                        {{?loc rdf:type ssso:Location.}}
                    }}.
                OPTIONAL 
                    {{
                        BIND (ssso:{uri} AS ?eq).
                        ?eq ssso:hasContext ?loc.
                        {{?loc rdf:type ssso:Location.}}
                    }}.
                OPTIONAL 
                    {{
                        BIND (ssso:{uri} AS ?svc).
                        ?svc rdf:type ?svcclass.
                        ?svcclass rdfs:subClassOf ?topclass.
                        ?topclass rdfs:subClassOf ssso:Service.
                        ?eq ssso:hasService ?svc.
                        ?eq ssso:hasContext ?loc.
                        {{?loc rdf:type ssso:Group.}}
                    }}.
                OPTIONAL 
                    {{
                        BIND (ssso:{uri} AS ?eq).
                        ?eq ssso:hasContext ?loc.
                        {{?loc rdf:type ssso:Group.}}
                    }}.
            }}
            """
        res = self.query(q)
        try:
            return res[0][0].split(':')[-1]
        except:
            return None

    def get_env_threat_list(self, uri):
        """
        Return the list of threat in a location/Group
        :param uri: location/group uri
        :return: [(threat uri, threat class, threat level)]
        """
        q = f"""
            SELECT ?threat ?threat_class ?threat_level
            WHERE
            {{
                ?threat rdf:type ?threat_class.
                ?threat_class rdfs:subClassOf ssso:Threat.
                ?threat_level rdf:type ssso:Threat_Level.
                ?threat ssso:hasContext ssso:{uri}.
                ?threat ssso:hasPolicy ?threat_level.

        }}
        """
        try:
            res = self.query(q)
            res = [(item[0].split(':')[-1], item[1].split(':')[-1], int(item[2][-1])) for item in res]
            return res
        except:
            return None

    def get_all_services_in_env(self, env, status='Active'):
        """
        Return the list of services in a location/group
        :param env: location/group uri
        :param status: Active/Inactive/Suspended
        :return: [(service uri, hasValue json)]
        """
        q = f"""
            SELECT ?svc ?value
            WHERE
            {{
                BIND (ssso:{env} AS ?env).
                ?svc rdf:type ?svc_class.
                ?eqp rdf:type ?eqp_class.
                ?eqp_class rdfs:subClassOf ?eqp_top_class.
                ?svc_class rdfs:subClassOf ?svc_top_class.
                ?svc_top_class rdfs:subClassOf ssso:Service.
                ?eqp_top_class rdfs:subClassOf ssso:Equipment.
                ?eqp ssso:hasContext ?env.
                ?eqp ssso:hasService ?svc.
                ?svc ssso:hasContext ssso:{status}.
                OPTIONAL{{?svc ssso:hasValue ?value.}}
        }}
        """
        res = self.query(q)
        try:
            res = [(item[0].split(':')[-1], json.loads(item[1]) if item[1] is not None else {}) for item in res]
            return res
        except:
            return None

    def list_auth_by_rejectedsvc(self, rejectedServiceUUID, Lock=False):
        """
        Return all authentication services with the same location as the rejected service
        If Lock is true, only return auth svc provided by locks
        """
        if not Lock:
            q = f"""
            SELECT ?svcclass ?svc ?equipmentclass ?equipment ?loc
            WHERE
            {{
                BIND (ssso:{rejectedServiceUUID} AS ?rejsvc).
                ?loc rdf:type ssso:Location.
                ?svchost ssso:hasService ?rejsvc.
                ?svchost ssso:hasContext ?loc.
                ?equipment ssso:hasContext ?loc.
                ?equipment ssso:hasService ?svc.
                ?equipment rdf:type ?equipmentclass.
                ?equipmentclass rdfs:subClassOf ?eqtopclass.
                FILTER (?eqtopclass IN (ssso:AV, ssso:Telecommunication)). 
                ?svc rdf:type ?svcclass.
                ?svcclass rdfs:subClassOf ssso:Authentication.
        }}
        """
            res = self.query(q)
            res = [tuple([uri.split(':')[-1] if uri is not None else None for uri in item]) for item in res]
            return res
        else:
                q = f"""
                SELECT ?svcclass ?svc ?equipmentclass ?equipment ?loc
                WHERE
                {{
                    BIND (ssso:{rejectedServiceUUID} AS ?rejsvc).
                    ?loc rdf:type ssso:Location.
                    ?svchost ssso:hasService ?rejsvc.
                    ?svchost ssso:hasContext ?loc.
                    ?equipment ssso:hasContext ?loc.
                    ?equipment ssso:hasService ?svc.
                    ?equipment rdf:type ?equipmentclass.
                    ?equipmentclass rdfs:subClassOf ssso:Lock.
                    ?svc rdf:type ?svcclass.
                    ?svcclass rdfs:subClassOf ssso:Authentication.
            }}
            """
                res = self.query(q)
                res = [tuple([uri.split(':')[-1] if uri is not None else None for uri in item]) for item in res]
                return res