import json
import uuid
from SSSO.sssontology import sssontology
import SSSO.exceptions
from SSSO.utils import endpoint_request
from rdflib import RDFS, RDF, Namespace, Graph, URIRef, OWL, Literal, XSD
import numpy as np
from datetime import datetime


class Equipment(object):
    def __init__(self, ontology):
        self.ontology = ontology
        assert type(self.ontology) == sssontology

    def create(self, equipmentModel, context=None):
        """
        :param equipmentModel: "UUID" or {data}
        :PARAM UUID: "New Equipment UUID"
        :return: Equipment UUID if created otherwise None
        """
        bulk_updates = []
        svc_bulk_updates =[]
        if type(equipmentModel) == str:
            equipmentModel = self.ontology.query_data(object=equipmentModel, object_class='Equipment_Model')
            if equipmentModel == []:
                raise SSSO.exceptions.URIDoesNotExist
            else:
                EQM_UUID = equipmentModel
                equipmentModel = json.loads(equipmentModel[0][0])
        else:
            EQM_UUID = equipmentModel.get('uuid', None)
            assert EQM_UUID is not None
            if self.ontology.exists(EQM_UUID):
                raise SSSO.exceptions.URIAlreadyExists(EQM_UUID, 'Equipment Model')
            # Create a new Equipment Model
            bulk_updates +=[
                (self.ontology.ssso[EQM_UUID], RDF.type, self.ontology.ssso['Equipment_Model']),
                (self.ontology.ssso[EQM_UUID], self.ontology.ssso['hasClass'], Literal(equipmentModel.get('Equipment Class'))),
                (self.ontology.ssso[EQM_UUID], self.ontology.ssso['hasName'], Literal(equipmentModel.get('Equipment Model Name'))),
                (self.ontology.ssso[EQM_UUID], self.ontology.ssso['hasData'], Literal(json.dumps(equipmentModel).replace('"', '\\"'))),
                (self.ontology.ssso[EQM_UUID], self.ontology.ssso['hasDescription'], Literal(str(equipmentModel.get('Description')).replace('"', '\\"')))
            ]
        # Create a new Equipment
        equipmentUUID = str(uuid.uuid4())
        bulk_updates.append((self.ontology.ssso[equipmentUUID], RDF.type, self.ontology.ssso[equipmentModel.get('Equipment Class')]))
        bulk_updates.append((self.ontology.ssso[equipmentUUID], self.ontology.ssso['hasContext'], self.ontology.ssso[EQM_UUID]))

        # # Add context attributes
        for key, value in context.items():
            self.ontology.get_or_add_object(object=value, object_class=key)
            bulk_updates.append((self.ontology.ssso[equipmentUUID], self.ontology.ssso['hasContext'], self.ontology.ssso[value]))
            self.ontology.get_or_add_object(value, key)

        # Add (register) new services
        for item in equipmentModel.get('Service'):
            serviceUUID = str(uuid.uuid4())
            serviceName = item.get('Name')
            serviceClass = item.get('Service Class')
            serviceRequiredSecurityLevel = item.get('Required Security Level')
            serviceSecurityLevelProvided = item.get('Security Level Provided')
            serviceSecurityAssessmentPolicy = item.get('Security Assessment Policy')
            serviceAccessPolicy = item.get('Access Policy')
            serviceTrustLevelAssessmentPolicy = item.get('Trust Level Assessment Policy')
            serviceMetadata = item.get('Request Model')
            serviceEndpoints = item.get('Resource Name')
            svc_bulk_updates.append((self.ontology.ssso[serviceUUID], self.ontology.ssso['hasContext'], self.ontology.ssso['Inactive']))
            bulk_updates += [
                (self.ontology.ssso[serviceUUID], RDF.type, self.ontology.ssso[serviceClass]),
                (self.ontology.ssso[serviceUUID], self.ontology.ssso['hasName'], Literal(serviceName)),
                (self.ontology.ssso[equipmentUUID], self.ontology.ssso['hasService'], self.ontology.ssso[serviceUUID])]
            if serviceRequiredSecurityLevel is not None:
                bulk_updates.append((self.ontology.ssso[serviceUUID], self.ontology.ssso['hasPolicy'], self.ontology.ssso[serviceRequiredSecurityLevel]))
            if serviceSecurityLevelProvided is not None:
                bulk_updates.append((self.ontology.ssso[serviceUUID], self.ontology.ssso['hasPolicy'], self.ontology.ssso[serviceSecurityLevelProvided]))
            if serviceSecurityAssessmentPolicy is not None:
                if not self.ontology.exists(serviceSecurityAssessmentPolicy):
                    raise SSSO.exceptions.URIDoesNotExist(serviceSecurityAssessmentPolicy, 'Security_Assessment_Policy')
                bulk_updates.append((self.ontology.ssso[serviceUUID], self.ontology.ssso['hasPolicy'], self.ontology.ssso[serviceSecurityAssessmentPolicy]))
            if serviceAccessPolicy is not None:
                if not self.ontology.exists(serviceAccessPolicy):
                    raise SSSO.exceptions.URIDoesNotExist(serviceAccessPolicy, 'Access_Policy')
                bulk_updates.append((self.ontology.ssso[serviceUUID], self.ontology.ssso['hasPolicy'], self.ontology.ssso[serviceAccessPolicy]))
            if serviceTrustLevelAssessmentPolicy is not None:
                if not self.ontology.exists(serviceTrustLevelAssessmentPolicy):
                    raise SSSO.exceptions.URIDoesNotExist(serviceTrustLevelAssessmentPolicy, 'Trust_Level_Assessment_Policy')
                bulk_updates.append((self.ontology.ssso[serviceUUID], self.ontology.ssso['hasPolicy'], self.ontology.ssso[serviceTrustLevelAssessmentPolicy]))
            if serviceMetadata is not None:
                if not self.ontology.exists(serviceMetadata):
                    raise SSSO.exceptions.URIDoesNotExist(serviceMetadata,'Request Model')
                bulk_updates.append((self.ontology.ssso[serviceUUID], self.ontology.ssso['hasContext'],
                                         self.ontology.ssso[serviceMetadata]))
            for protocol, resource_name in serviceEndpoints.items():
                endpointUUID = str(uuid.uuid4())
                bulk_updates.append((self.ontology.ssso[endpointUUID], RDF.type, self.ontology.ssso[protocol]))
                bulk_updates.append((self.ontology.ssso[endpointUUID], self.ontology.ssso['hasData'], Literal('{}{}'.format(equipmentUUID, resource_name))))
                bulk_updates.append((self.ontology.ssso[serviceUUID], self.ontology.ssso['hasContext'], self.ontology.ssso[endpointUUID]))
        # Add Threats (model)
        for item in equipmentModel.get('threat'):
            threatmodelUUID = str(uuid.uuid4())
            threatAssessmentPolicy = item.get('Threat Assessment Policy')
            threatMitigationPolicy = item.get('Threat Mitigation Policy')
            threatLevel = item.get('Threat Level')
            threatClass = item.get('Threat Class')
            assert threatClass is not None
            bulk_updates += [
                (self.ontology.ssso[threatmodelUUID], RDF.type, self.ontology.ssso['Threat_Model']),
                (self.ontology.ssso[threatmodelUUID], self.ontology.ssso['hasName'], Literal(item.get('Name'))),
                (self.ontology.ssso[threatmodelUUID], self.ontology.ssso['hasClass'],  Literal(threatClass)),
                (self.ontology.ssso[equipmentUUID], self.ontology.ssso['hasContext'], self.ontology.ssso[threatmodelUUID])
            ]
            if threatAssessmentPolicy is not None:
                if not self.ontology.exists(threatAssessmentPolicy):
                    raise SSSO.exceptions.URIDoesNotExist(threatAssessmentPolicy, 'Threat_Assessment_Policy')
                bulk_updates.append((self.ontology.ssso[threatmodelUUID], self.ontology.ssso['hasPolicy'], self.ontology.ssso[threatAssessmentPolicy]))
            if threatMitigationPolicy is not None:
                if not self.ontology.exists(threatMitigationPolicy):
                    raise SSSO.exceptions.URIDoesNotExist(threatMitigationPolicy, 'Threat_Mitigation_Policy')
                bulk_updates.append((self.ontology.ssso[threatmodelUUID], self.ontology.ssso['hasPolicy'], self.ontology.ssso[threatMitigationPolicy]))
            if threatLevel is not None:
                bulk_updates.append((self.ontology.ssso[threatmodelUUID], self.ontology.ssso['hasPolicy'], self.ontology.ssso[threatLevel]))
        # Bulk add changes
        self.ontology.bulk_insert(bulk_updates)
        self.ontology.bulk_insert(svc_bulk_updates)
        return equipmentUUID

    def remove(self, equipmentUUID):
        assert self.ontology.exists(equipmentUUID) == True
        query_q = f"""
        DELETE {{?s ?p ?o}}
        WHERE
        {{
            {{
                ?s ?p ?o.
                VALUES ?s {{ssso:{equipmentUUID}}}.
            }}
            UNION
            {{
                ?s ?p ?o.
                VALUES ?eq {{ssso:{equipmentUUID}}}.
                ?eq ssso:hasService ?svc.
                ?svc ?p ?o.
            }}
            UNION
            {{
                ?s ?p ?o.
                VALUES ?eq {{ssso:{equipmentUUID}}}.
                ?eq ssso:hasService ?svc.
                ?svc ssso:hasContext ?conpol.
                FILTER NOT EXISTS  {{?conpol rdf:type ssso:Request_Model}}.
                ?conpol ?p ?o.
            }}
            UNION
            {{
                ?s ?p ?o.
                VALUES ?eq {{ssso:{equipmentUUID}}}.
                ?eq ssso:hasContext ?eqcon.
                {{?eqcon rdf:type ssso:Threat_Model}} UNION {{?eqcon rdf:type ssso:Request_Model }}.
                ?eqcon ?p ?o.
            }}
}}"""
        self.ontology.update(query_q)

    def list_service_on_device(self, deviceUUID):
        """
        List all services on a device
        :param deviceUUID: deviceUUID
        """
        assert self.ontology.exists(deviceUUID) == True
        res = self.ontology.list_service_on_device(equipmentUUID=deviceUUID)
        res = [(item[0].split(':')[-1], item[1].split(':')[-1]) for item in res]
        return res

class Service(object):
    def __init__(self, ontology):
        self.ontology = ontology
        self.Policy = Policy(ontology)
        assert type(self.ontology) == sssontology

    def enable(self, serviceUUID, userUUID):
        assert self.ontology.exists(serviceUUID) == True
        serviceTopClass = self.ontology.get_top_class(serviceUUID)
        # If the requested service is an authentication service
        if serviceTopClass == 'Authentication':
            User_TrustLevel = self.ontology.get_user_trust_level(userUUID)
            User_TrustLevel = 0 if User_TrustLevel is None else User_TrustLevel
            User_Data = self.ontology.query_data(object=userUUID, object_class='User')
            User_Data = json.loads(User_Data[0][0]) if User_Data!=[] else {}
            Previous_Authentication_Methods = User_Data.get('Authentication', [])
            Current_Authentication_Method = self.ontology.get_class(serviceUUID)
            if Current_Authentication_Method in Previous_Authentication_Methods:
                return (False, 'Repeated')
            endpoint_list = self.ontology.get_endpoint_list(endpoint_sparql='?Service ssso:hasContext ?Endpoint.', userUUID=userUUID, serviceUUID=serviceUUID)
            protocol, address, request_model = self.ontology.query_endpoint(endpoint_list[0])
            auth_res = endpoint_request(prtc=protocol, addr=address, rqm=request_model)
            if auth_res is False:
                return (False, 'Authentication Failed: Invalid Credentials')
            SLTLAP_list = self.ontology.get_required_SLTLAP(serviceUUID)
            if SLTLAP_list is None:
                return (False, 'TLAP')  # Due to trust level assessment policy, the authentication trust level can not be evaluated
            SLTLAPClass = SLTLAP_list[0][1].toPython()
            if SLTLAPClass == 'Trust_Level':
                Provided_TrustLevel = SLTLAP_list[0][0].split(':')[-1]
                New_TrustLevel = np.min([4, int(Provided_TrustLevel[-1])+User_TrustLevel])
                New_TrustLevel = f'SL-{New_TrustLevel}'
                self.ontology.update_user_trust_level(userUUID, New_TrustLevel)
                Previous_Authentication_Methods.append(Current_Authentication_Method)
                User_Data['Authentication'] = Previous_Authentication_Methods
                self.ontology.update_data_literal(individualURI=userUUID, data=json.dumps(User_Data).replace('"', '\\"'))
                return (True, New_TrustLevel)
            elif SLTLAPClass == 'Trust_Level_Assessment_Policy':
                SLTLAP_list = [item[0].split(':')[-1] for item in SLTLAP_list]
                evaluation_res = self.Policy.evaluate_trust_level_assessment_policy_list(SLTLAP_list, userUUID, serviceUUID)
                if evaluation_res is None:
                    return (False, 'Authentication Failed: Trust Level Assessment Policy')
                New_TrustLevel = np.min([4, int(evaluation_res[-1])+User_TrustLevel])
                New_TrustLevel = f'SL-{New_TrustLevel}'
                self.ontology.update_user_trust_level(userUUID, New_TrustLevel)
                Previous_Authentication_Methods.append(Current_Authentication_Method)
                User_Data['Authentication'] = Previous_Authentication_Methods
                self.ontology.update_data_literal(individualURI=userUUID, data=json.dumps(User_Data).replace('"', '\\"'))
                return (True, New_TrustLevel)
        # If the requested service is a data/control/sense service
        SLAP_list = self.ontology.get_required_SLAP(serviceUUID)
        if SLAP_list is None:
            return (False, 'AP') # Due to access policy, the request is denied
        SLClass = SLAP_list[0][1].toPython()
        if userUUID == 'MAPE-k': # Accept all MAPE-k engine internal requests
            endpoint_list = self.ontology.get_endpoint_list(endpoint_sparql='?Service ssso:hasContext ?Endpoint.',
                                                            userUUID=userUUID, serviceUUID=serviceUUID)
            protocol, address, request_model = self.ontology.query_endpoint(endpoint_list[0])
            endpoint_request(prtc=protocol, addr=address, rqm=request_model)
            self.ontology.update_triple(serviceUUID, 'hasContext', 'Active', 'Status')
            accepted_service_metadata = {"Requester": userUUID,
                                         "Timestamp": datetime.today().strftime('%Y-%m-%dT%H:%M:%S+00:00')}
            self.ontology.update_service_value(serviceUUID, json.dumps(accepted_service_metadata))
            return (True, 'Accepted')
        if SLClass == 'Security_Level':
            # If the service requires a certain security level
            Required_SecurityLevel = int(SLAP_list[0][0][-1])
            User_TrustLevel = self.ontology.get_user_trust_level(userUUID)
            User_TrustLevel = 0 if User_TrustLevel is None else User_TrustLevel
            Env_SecurityLevel = self.ontology.get_env_security_level_and_classification_level(serviceUUID)
            Env_SecurityLevel, Env_ClassificationLevel = (0, 'Classified') if Env_SecurityLevel is None else Env_SecurityLevel
            Env_ClassificationLevel_to_par = {'Classified':0, 'Normal':2, 'Public':4}
            Env_ClassificationTurningPar = Env_ClassificationLevel_to_par.get(Env_ClassificationLevel)
            if(User_TrustLevel>=Env_SecurityLevel):
                if(Env_SecurityLevel>=Required_SecurityLevel-Env_ClassificationTurningPar):
                    endpoint_list = self.ontology.get_endpoint_list(endpoint_sparql='?Service ssso:hasContext ?Endpoint.', userUUID=userUUID, serviceUUID=serviceUUID)
                    protocol, address, request_model = self.ontology.query_endpoint(endpoint_list[0])
                    endpoint_request(prtc=protocol, addr=address, rqm=request_model)
                    self.ontology.update_triple(serviceUUID, 'hasContext', 'Active', 'Status')
                    accepted_service_metadata = {"Requester":userUUID,
                                                 "Timestamp":datetime.today().strftime('%Y-%m-%dT%H:%M:%S+00:00'),
                                                 "Required Security Level":f"SL-{Required_SecurityLevel}"}
                    self.ontology.update_service_value(serviceUUID, json.dumps(accepted_service_metadata))
                    return (True, 'Accepted')
                else:
                    return (False, 'Securiry_Level', Required_SecurityLevel-Env_ClassificationTurningPar-Env_SecurityLevel)
            else:
                return (False, 'Trust_Level', np.max([Env_SecurityLevel-User_TrustLevel, Required_SecurityLevel-User_TrustLevel]))
        elif SLClass == 'Access_Policy':
            AP_list = [item[0].split(':')[-1] for item in SLAP_list]
            evaluation_res = self.Policy.evaluate_access_policy_list(AP_list, userUUID, serviceUUID)
            if evaluation_res:
                endpoint_list = self.ontology.get_endpoint_list(
                endpoint_sparql='?Service ssso:hasContext ?Endpoint.', userUUID=userUUID, serviceUUID=serviceUUID)
                protocol, address, request_model = self.ontology.query_endpoint(endpoint_list[0])
                endpoint_request(prtc=protocol, addr=address, rqm=request_model)
                self.ontology.update_triple(serviceUUID, 'hasContext', 'Active', 'Status')
                accepted_service_metadata = {"Requester": userUUID,
                                             "Timestamp": datetime.today().strftime('%Y-%m-%dT%H:%M:%S+00:00'),
                                             "Required Security Level": f"AP"}
                self.ontology.update_service_value(serviceUUID,
                                                    json.dumps(accepted_service_metadata))
                return (True, 'Accepted')
            else:
                return (False, 'Access_Policy')
        elif SLClass == 'Security_Assessment_Policy':
            SAP_list = [item[0].split(':')[-1] for item in SLAP_list]
            evaluation_res = self.Policy.evaluate_security_level_assessment_policy_list(SAP_list, userUUID, serviceUUID)
            if evaluation_res is None:
                return (False, 'SAP')
            Required_SecurityLevel = int(evaluation_res[-1])
            User_TrustLevel = self.ontology.get_user_trust_level(userUUID)
            User_TrustLevel = 0 if User_TrustLevel is None else User_TrustLevel
            Env_SecurityLevel = self.ontology.get_env_security_level_and_classification_level(serviceUUID)
            Env_SecurityLevel, Env_ClassificationLevel = (0, 'Classified') if Env_SecurityLevel is None else Env_SecurityLevel
            Env_ClassificationLevel_to_par = {'Classified':0, 'Normal':2, 'Public':4}
            Env_ClassificationTurningPar = Env_ClassificationLevel_to_par.get(Env_ClassificationLevel)
            if(User_TrustLevel>=Env_SecurityLevel):
                if(Env_SecurityLevel>=Required_SecurityLevel-Env_ClassificationTurningPar):
                    endpoint_list = self.ontology.get_endpoint_list(endpoint_sparql='?Service ssso:hasContext ?Endpoint.', userUUID=userUUID, serviceUUID=serviceUUID)
                    protocol, address, request_model = self.ontology.query_endpoint(endpoint_list[0])
                    endpoint_request(prtc=protocol, addr=address, rqm=request_model)
                    self.ontology.update_triple(serviceUUID, 'hasContext', 'Active', 'Status')
                    accepted_service_metadata = {"Requester":userUUID,
                                                 "Timestamp":datetime.today().strftime('%Y-%m-%dT%H:%M:%S+00:00'),
                                                 "Required Security Level":f"SL-{Required_SecurityLevel}"}
                    self.ontology.update_service_value(serviceUUID, json.dumps(accepted_service_metadata))
                    return (True, 'Accepted')
                else:
                    return (False, 'Securiry_Level', Required_SecurityLevel-Env_ClassificationTurningPar-Env_SecurityLevel)
            else:
                return (False, 'Trust_Level', np.max([Env_SecurityLevel-User_TrustLevel, Required_SecurityLevel-User_TrustLevel]))

    def suspend(self, serviceUUID):
        assert self.ontology.exists(serviceUUID) == True
        self.ontology.update_triple(serviceUUID, 'hasContext', 'Suspended', 'Status')

    def disable(self, serviceUUID):
        assert self.ontology.exists(serviceUUID) == True
        self.ontology.update_triple(serviceUUID, 'hasContext', 'Inactive', 'Status')

    def recommend_auth(self, rejectedServiceUUID, userUUID, Lock=False):
        auth_svc_list = self.ontology.list_auth_by_rejectedsvc(rejectedServiceUUID, Lock)
        User_Data = self.ontology.query_data(object=userUUID, object_class='User')
        User_Data = json.loads(User_Data[0][0]) if User_Data != [] else {}
        Previous_Authentication_Methods = User_Data.get('Authentication', [])
        for item in auth_svc_list:
            if item[0] is not None and item[0] not in Previous_Authentication_Methods:
                authclass, authsvcuri, equipmentclass, equipmenturi, location = item
                return (authclass, authsvcuri, equipmentclass, equipmenturi, location)
        return None


class Policy(object):
    def __init__(self, ontology):
        self.ontology = ontology
        assert type(self.ontology) == sssontology

    def evaluate_trust_level_assessment_policy_list(self, policyList, userUUID, serviceUUID):
        policyList = [self.ontology.query_data(f"{item}") for item in policyList]
        policyList = [json.loads(item[0][0]) for item in policyList]
        priorityList = [item.get('Priority') for item in policyList]
        maxPriority = np.max(priorityList)
        policy = policyList[priorityList.index(maxPriority)]
        self.refresh_data(policy, userUUID, serviceUUID)
        policy = json.loads(self.ontology.query_data(f"ssso:{policy}")[0][0]) if type(policy) is str else policy
        # If the trust level assessment policy is empty, the provided trust level is 0.
        return self.ontology.evaluate_Trust_Level_Assessment_Policy(policy.get('Policy', "BIND(ssso:SL-0 as ?Trust_Level)"), userUUID, serviceUUID)

    def evaluate_security_level_assessment_policy_list(self, policyList, userUUID, serviceUUID):
        policyList = [self.ontology.query_data(f"{item}") for item in policyList]
        policyList = [json.loads(item[0][0]) for item in policyList]
        priorityList = [item.get('Priority') for item in policyList]
        maxPriority = np.max(priorityList)
        policy = policyList[priorityList.index(maxPriority)]
        self.refresh_data(policy, userUUID, serviceUUID)
        policy = json.loads(self.ontology.query_data(f"ssso:{policy}")[0][0]) if type(policy) is str else policy
        # If the security level assessment policy is empty, the required security level is SL-4.
        return self.ontology.evaluate_Security_Level_Assessment_Policy(policy.get('Policy', "BIND(ssso:SL-4 as ?Security_Level)"), userUUID, serviceUUID)

    def evaluate_access_policy_list(self, policyList, userUUID, serviceUUID):
        policyList = [self.ontology.query_data(f"{item}") for item in policyList]
        policyList = [json.loads(item[0][0]) for item in policyList]
        priorityList = [item.get('Priority') for item in policyList]
        maxPriority = np.max(priorityList)
        policy = policyList[priorityList.index(maxPriority)]
        self.refresh_data(policy, userUUID, serviceUUID)
        policy = json.loads(self.ontology.query_data(f"ssso:{policy}")[0][0]) if type(policy) is str else policy
        # If the access policy is empty, reject this request.
        return self.ontology.evaluate_Access_Policy(policy.get('Policy', 'FILTER(True=False).'), userUUID, serviceUUID)

    def evaluate_threat_assessment_policy_list(self, policyList, equipmentUUID, Threat_Class, envUUID):
        policyList = [self.ontology.query_data(f"{item}") for item in policyList]
        policyList = [json.loads(item[0][0]) for item in policyList]
        priorityList = [item.get('Priority') for item in policyList]
        maxPriority = np.max(priorityList)
        policy = policyList[priorityList.index(maxPriority)]
        self.refresh_data_TAP(policy, equipmentUUID, envUUID)
        policy = json.loads(self.ontology.query_data(f"ssso:{policy}")[0][0]) if type(policy) is str else policy
        # If the threat assessment policy is empty, return TL-4 for the sake of safety
        return self.ontology.evaluate_Threat_Assessment_Policy(policy.get('Policy', 'BIND(ssso:TL-4 as ?Threat_Level)'), equipmentUUID, Threat_Class, envUUID)

    def evaluate_threat_mitigation_policy_list(self, policyList, equipmentUUID, Threat_Class, envUUID):
        policyList = [self.ontology.query_data(f"{item}") for item in policyList]
        policyList = [json.loads(item[0][0]) for item in policyList]
        priorityList = [item.get('Priority') for item in policyList]
        maxPriority = np.max(priorityList)
        policy = policyList[priorityList.index(maxPriority)]
        self.refresh_data_TAP(policy, equipmentUUID, envUUID)
        policy = json.loads(self.ontology.query_data(f"ssso:{policy}")[0][0]) if type(policy) is str else policy
        # If the threat assessment policy is empty, return TL-4 for the sake of safety
        return self.ontology.evaluate_Threat_Mitigation_Policy(policy.get('Policy', ''), equipmentUUID, Threat_Class, envUUID)

    def refresh_data(self, policy, userUUID, serviceUUID):
        policy = json.loads(self.ontology.query_data(f"ssso:{policy}")[0][0]) if type(policy) is str else policy
        endpoint = policy.get('Endpoint', {})
        if endpoint.get('Type')=='SPARQL':
            endpoint_list = self.ontology.get_endpoint_list(endpoint_sparql=endpoint.get('Data'), userUUID=userUUID, serviceUUID=serviceUUID)
            if endpoint_list is None:
                raise SSSO.exceptions.EndpointInaccessible(endpoint_list)
        elif endpoint.get('Type')=='URI':
            endpoint_list = endpoint.get('Data')
        else:
            endpoint_list = []
        for endpoint in endpoint_list:
            protocol, address, request_model = self.ontology.query_endpoint(endpoint)
            endpoint_data = endpoint_request(prtc=protocol, addr=address, rqm=request_model)
            self.ontology.update_endpoint_value(endpoint, endpoint_data)

    def refresh_data_TAP(self, policy, equipmentUUID, envUUID):
        policy = json.loads(self.ontology.query_data(f"ssso:{policy}")[0][0]) if type(policy) is str else policy
        endpoint = policy.get('Endpoint', {})
        if endpoint.get('Type')=='SPARQL':
            endpoint_list = self.ontology.get_endpoint_list_TAP(endpoint_sparql=endpoint.get('Data'), equipmentUUID=equipmentUUID, envUUID=envUUID)
            if endpoint_list is None:
                raise SSSO.exceptions.EndpointInaccessible(endpoint_list)
        elif endpoint.get('Type')=='URI':
            endpoint_list = endpoint.get('Data')
        else:
            endpoint_list = []
        for endpoint in endpoint_list:
            protocol, address, request_model = self.ontology.query_endpoint(endpoint)
            endpoint_data = endpoint_request(prtc=protocol, addr=address, rqm=request_model)
            self.ontology.update_endpoint_value(endpoint, endpoint_data)


    def add_policy(self, policyDict, policyClass):
        policyUUID = policyDict.get('uuid', None)
        assert policyUUID is not None
        assert policyClass in ['Access_Policy', 'Security_Assessment_Policy', 'Threat_Assessment_Policy', 'Threat_Mitigation_Policy', 'Trust_Level_Assessment_Policy']
        if self.ontology.exists(policyUUID):
            raise SSSO.exceptions.URIAlreadyExists(policyUUID, policyClass)
        bulk_updates = []
        bulk_updates += [
            (self.ontology.ssso[policyUUID], RDF.type, self.ontology.ssso[policyClass]),
            (self.ontology.ssso[policyUUID], self.ontology.ssso['hasData'], Literal(json.dumps(policyDict).replace('"', '\\"'))),
            (self.ontology.ssso[policyUUID], self.ontology.ssso['hasName'], Literal(policyDict.get('Name', 'Unnamed'))),
            (self.ontology.ssso[policyUUID], self.ontology.ssso['hasDescription'], Literal(policyDict.get('Description', 'Empty')))
        ]
        self.ontology.bulk_insert(bulk_updates)
        return policyUUID

    def remove_policy(self, policyUUID):
        if self.ontology.exists(policyUUID):
            raise SSSO.exceptions.URIDoesNotExist(policyUUID)
        self.ontology.delete_policy(policyUUID)
        return True

    def bind_policy_to_individual(self, individualURI, policyURI):
        assert self.ontology.exists(individualURI) == True
        assert self.ontology.exists(policyURI) == True
        self.ontology.add_individual_policy(individualURI, policyURI)

    def remove_policy_of_individual(self, individualURI, policyURI):
        assert self.ontology.exists(individualURI) == True
        assert self.ontology.exists(policyURI) == True
        self.ontology.remove_triple(subject=individualURI, property='hasPolicy', object=policyURI)


class Event(object):
    def __init__(self, ontology):
        self.ontology = ontology
        assert type(self.ontology) == sssontology
        self.Policy = Policy(self.ontology)
        self.Service = Service(self.ontology)

    def report_threat(self, equipmentUUID, Threat_Class, envUUID=None):
        # Report a threat to the engine
        status, ThreatUUID, newEnvSL_or_msg = self.add_threat(equipmentUUID, Threat_Class, envUUID)
        if not status:
            return (False, newEnvSL_or_msg)
        LocGrp = self.ontology.get_location(equipmentUUID) if envUUID is None else envUUID  # Get the Loation/Group of the equipment
        active_service_list = self.ontology.get_all_services_in_env(env=LocGrp, status='Active')
        service_to_suspend = []
        for service in active_service_list:
            res = self.Service.enable(serviceUUID=service[0], userUUID=service[1].get('Requester', 'ASMEngine'))
            if not res[0]:
                service_to_suspend.append(service[0])
                endpoint_list = self.ontology.get_endpoint_list(
                    endpoint_sparql='?Service ssso:hasContext ?Endpoint.', userUUID=service[1].get('Requester', 'ASMEngine'), serviceUUID=service[0])
                protocol, address, request_model = self.ontology.query_endpoint(endpoint_list[0])
                endpoint_request(prtc=protocol, addr=address, rqm=request_model)
                self.ontology.update_triple(service[0], 'hasContext', 'Suspended', 'Status')
        return (True, ThreatUUID, newEnvSL_or_msg, service_to_suspend)

    def remove_threat(self, ThreatUUID):
        assert self.ontology.exists(ThreatUUID) == True
        LocGrp = self.ontology.get_location(ThreatUUID)
        self.ontology.delete_threat(ThreatUUID)
        env_active_threat_list = self.ontology.get_env_threat_list(LocGrp)
        Env_SecurityLevel = self.evaluate_env_security_level(env_active_threat_list)
        self.ontology.update_env_security_level(LocGrp, Env_SecurityLevel)
        suspended_service_list = self.ontology.get_all_services_in_env(env=LocGrp, status='Suspended')
        service_to_enable = []
        for service in suspended_service_list:
            res = self.Service.enable(serviceUUID=service[0], userUUID=service[1].get('Requester', 'ASMEngine'))
            if res[0]:
                service_to_enable.append(service[0])
                endpoint_list = self.ontology.get_endpoint_list(
                    endpoint_sparql='?Service ssso:hasContext ?Endpoint.', userUUID=service[1].get('Requester', 'ASMEngine'), serviceUUID=service[0])
                protocol, address, request_model = self.ontology.query_endpoint(endpoint_list[0])
                endpoint_request(prtc=protocol, addr=address, rqm=request_model)
                self.ontology.update_triple(service[0], 'hasContext', 'Active', 'Status')
        return (True, Env_SecurityLevel, service_to_enable)


    def request_handler(self):
        pass
        return

    def evaluate_env_security_level(self, env_active_threat_list):
        N_TL1 = len(set([item[1] for item in env_active_threat_list if item[2]==1]))
        N_TL2 = len(set([item[1] for item in env_active_threat_list if item[2]==2]))
        N_TL3 = len(set([item[1] for item in env_active_threat_list if item[2]==3]))
        N_TL4 = len(set([item[1] for item in env_active_threat_list if item[2]==4]))
        if N_TL1>=4:
            N_TL2 += 1
        if N_TL2>=3:
            N_TL3 += 1
        if N_TL3>=2:
            N_TL4 += 1
        if N_TL4!=0:
            Threat_Level = 4
        elif N_TL3!=0:
            Threat_Level = 3
        elif N_TL2!=0:
            Threat_Level = 2
        elif N_TL1!=0:
            Threat_Level = 1
        else:
            Threat_Level = 0
        New_Security_Level = 4 - Threat_Level
        return New_Security_Level



    def add_threat(self, equipmentUUID, Threat_Class, envUUID=None):
        # Add a new threat to an environment and re-evaluate the security level of the env
        assert self.ontology.exists(equipmentUUID) == True
        assert self.ontology.exists(Threat_Class) == True
        LocGrp = self.ontology.get_location(equipmentUUID) if envUUID is None else envUUID  # Get the Loation/Group of the equipment
        TLTAP_list = self.ontology.get_TLTAP(equipmentUUID=equipmentUUID, Threat_Class=Threat_Class)
        if TLTAP_list is None:
            return (False, None, 'TLTAP') # Due to unexpected TLTAP results, the threat event is not accepted
        TLClass = TLTAP_list[0][1].toPython()
        if TLClass == 'Threat_Level':
            # If the threat has a certain threat level
            Posed_Threat_Level = int(TLTAP_list[0][0][-1])
            ThreatUUID = str(uuid.uuid4())
            bulk_updates = []
            bulk_updates +=[
                (self.ontology.ssso[ThreatUUID], RDF.type, self.ontology.ssso[Threat_Class]),
                (self.ontology.ssso[ThreatUUID], self.ontology.ssso['hasContext'], self.ontology.ssso[LocGrp]),
                (self.ontology.ssso[ThreatUUID], self.ontology.ssso['hasEquipment'], self.ontology.ssso[equipmentUUID]),
                (self.ontology.ssso[ThreatUUID], self.ontology.ssso['hasPolicy'], self.ontology.ssso[f"TL-{Posed_Threat_Level}"])
            ]
            self.ontology.bulk_insert(bulk_updates)
            env_active_threat_list = self.ontology.get_env_threat_list(LocGrp)
            Env_SecurityLevel = self.evaluate_env_security_level(env_active_threat_list)
            self.ontology.update_env_security_level(LocGrp, Env_SecurityLevel)
            return (True, ThreatUUID, Env_SecurityLevel)
        elif TLClass == 'Threat_Assessment_Policy':
            TAP_list = [item[0].split(':')[-1] for item in TLTAP_list]
            evaluation_res = self.Policy.evaluate_threat_assessment_policy_list(TAP_list, equipmentUUID, Threat_Class, envUUID)
            if evaluation_res is None:
                return (False, None, 'TAP')
            Posed_Threat_Level = int(evaluation_res[-1])
            ThreatUUID = str(uuid.uuid4())
            bulk_updates = []
            bulk_updates +=[
                (self.ontology.ssso[ThreatUUID], RDF.type, self.ontology.ssso[Threat_Class]),
                (self.ontology.ssso[ThreatUUID], self.ontology.ssso['hasContext'], self.ontology.ssso[LocGrp]),
                (self.ontology.ssso[ThreatUUID], self.ontology.ssso['hasEquipment'], self.ontology.ssso[equipmentUUID]),
                (self.ontology.ssso[ThreatUUID], self.ontology.ssso['hasPolicy'], self.ontology.ssso[f"TL-{Posed_Threat_Level}"])
            ]
            self.ontology.bulk_insert(bulk_updates)
            env_active_threat_list = self.ontology.get_env_threat_list(LocGrp)
            Env_SecurityLevel = self.evaluate_env_security_level(env_active_threat_list)
            self.ontology.update_env_security_level(LocGrp, Env_SecurityLevel)
            return (True, ThreatUUID, Env_SecurityLevel)
        elif TLClass == 'Threat_Mitigation_Policy':
            TAP_list = [item[0].split(':')[-1] for item in TLTAP_list]
            evaluation_res = self.Policy.evaluate_threat_mitigation_policy_list(TAP_list, equipmentUUID, Threat_Class, envUUID)
            if evaluation_res is None:
                return (False, None, 'TMP')
            service_to_suspend, service_to_disable, service_to_enable, mitigated_threat_level = evaluation_res
            for svc in service_to_suspend:
                self.Service.suspend(svc)
            for svc in service_to_disable:
                self.Service.disable(svc)
            for svc in service_to_enable:
                self.Service.enable(serviceUUID=svc, userUUID='MAPE-k')
            Posed_Threat_Level = mitigated_threat_level
            ThreatUUID = str(uuid.uuid4())
            bulk_updates = []
            bulk_updates +=[
                (self.ontology.ssso[ThreatUUID], RDF.type, self.ontology.ssso[Threat_Class]),
                (self.ontology.ssso[ThreatUUID], self.ontology.ssso['hasContext'], self.ontology.ssso[LocGrp]),
                (self.ontology.ssso[ThreatUUID], self.ontology.ssso['hasEquipment'], self.ontology.ssso[equipmentUUID]),
                (self.ontology.ssso[ThreatUUID], self.ontology.ssso['hasPolicy'], self.ontology.ssso[f"TL-{Posed_Threat_Level}"])
            ]
            self.ontology.bulk_insert(bulk_updates)
            env_active_threat_list = self.ontology.get_env_threat_list(LocGrp)
            Env_SecurityLevel = self.evaluate_env_security_level(env_active_threat_list)
            self.ontology.update_env_security_level(LocGrp, Env_SecurityLevel)
            return (True, ThreatUUID, Env_SecurityLevel)

class Context(object):
    def __init__(self, ontology):
        self.ontology = ontology
        assert type(self.ontology) == sssontology

    def refresh_endpoint_data(self, endpoint_q, userUUID, serviceUUID):
        q = f"""
            SELECT ?Endpoint
            {{
                BIND (ssso:{userUUID} AS ?User).
                BIND (ssso:{serviceUUID} AS ?Service).
                ?Endpoint rdf:type ?class.
                ?class rdfs:subClassOf ?Communication_Endpiont.
                {endpoint_q}
            }}
            """
        endpoints = self.ontology.query(q)
        try:
            endpoints=[item.split(':')[-1] for item in endpoints[0]]
            for endpoint in endpoints:
                protocol, address, request_model = self.ontology.query_endpoint(endpoint)
                endpoint_data = endpoint_request(prtc=protocol, addr=address, rqm=request_model)
                self.ontology.update_endpoint_value(endpoint, endpoint_data)
        except:
            raise SSSO.exceptions.EndpointInaccessible

    def add_context(self, contextIndividual, contextClass, dataproperty=None, data=None, datatype='Literal'):
        assert contextClass in ['HTTP', 'MQTT', 'RPC', 'Group', 'Location', 'Metadata', 'Miscellaneous', 'Equipment_Model', 'Request_Model', 'Threat_Model', 'Variable']
        if self.ontology.exists(contextIndividual):
            raise SSSO.exceptions.URIAlreadyExists(contextIndividual)
        bulk_updates = []
        bulk_updates += [
            (self.ontology.ssso[contextIndividual], RDF.type, self.ontology.ssso[contextClass])
        ]
        if dataproperty is not None:
            if datatype == 'Literal':
                bulk_updates += [
                    (self.ontology.ssso[contextIndividual], self.ontology.ssso[dataproperty], Literal(data))
                ]
            elif datatype == 'XSD.integer':
                bulk_updates += [
                    (self.ontology.ssso[contextIndividual], self.ontology.ssso[dataproperty], Literal(data, datatype=XSD.integer))
                ]
            elif datatype == 'XSD.float':
                bulk_updates += [
                    (self.ontology.ssso[contextIndividual], self.ontology.ssso[dataproperty], Literal(data, datatype=XSD.float))
                ]
            elif datatype == 'XSD.boolean':
                bulk_updates += [
                    (self.ontology.ssso[contextIndividual], self.ontology.ssso[dataproperty], Literal(data, datatype=XSD.boolean))
                ]
            elif datatype == 'XSD.double':
                bulk_updates += [
                    (self.ontology.ssso[contextIndividual], self.ontology.ssso[dataproperty], Literal(data, datatype=XSD.double))
                ]
            elif datatype == 'XSD.dateTime':
                bulk_updates += [
                    (self.ontology.ssso[contextIndividual], self.ontology.ssso[dataproperty], Literal(data, datatype=XSD.dateTime))
                ]
            elif datatype == 'XSD.decimal':
                bulk_updates += [
                    (self.ontology.ssso[contextIndividual], self.ontology.ssso[dataproperty], Literal(data, datatype=XSD.decimal))
                ]
            elif datatype == 'XSD.string':
                bulk_updates += [
                    (self.ontology.ssso[contextIndividual], self.ontology.ssso[dataproperty], Literal(data, datatype=XSD.string))
                ]
        self.ontology.bulk_insert(bulk_updates)
        return True

    def bind_context_to_individual(self, individualURI, contextURI):
        assert self.ontology.exists(individualURI) == True
        assert self.ontology.exists(contextURI) == True
        self.ontology.add_individual_context(individualURI, contextURI)

    def remove_context_of_individual(self, individualURI, contextURI):
        assert self.ontology.exists(individualURI) == True
        assert self.ontology.exists(contextURI) == True
        self.ontology.remove_triple(subject=individualURI, property='hasContext', object=contextURI)


class User(object):
    def __init__(self, ontology):
        self.ontology = ontology
        assert type(self.ontology) == sssontology

    def add_user(self, user, context):
        if self.ontology.exists(user):
            raise SSSO.exceptions.URIAlreadyExists(user)
        bulk_updates = []
        bulk_updates += [
            (self.ontology.ssso[user], RDF.type, self.ontology.ssso['User'])
        ]
        # # Add context attributes
        for key, value in context.items():
            self.ontology.get_or_add_object(object=value, object_class=key)
            bulk_updates.append((self.ontology.ssso[user], self.ontology.ssso['hasContext'], self.ontology.ssso[value]))
            self.ontology.get_or_add_object(value, key)
        self.ontology.bulk_insert(bulk_updates)
        return True


class Manager(object):
    def __init__(self, ttl_filename=None, jena_address=None):
        self.ontology = sssontology(filename=ttl_filename, jena_address=jena_address)
        self.equipment = Equipment(self.ontology)
        self.service = Service(self.ontology)
        self.event = Event(self.ontology)
        self.policy = Policy(self.ontology)
        self.context = Context(self.ontology)
        self.user = User(self.ontology)

if __name__ == '__main__':
    manager = Manager('ssso_v1.ttl')
    manager = Manager('ssso_large_scale.ttl')
    with open('../EQM_Projector_ModelA.json') as json_file:
        SmartBoard_EQM = json.load(json_file)
    with open('../equipment_context.json') as json_file:
        SmartBoard_Context = json.load(json_file)
    #print(manager.equipment.create(equipmentModel=SmartBoard_EQM, context=SmartBoard_Context))
    #print(manager.equipment.create(equipmentModel='ae137288-3782-432d-8d83-d5cee733fe4b', context=SmartBoard_Context))
    # for i in range(4807):
    #     manager.equipment.create(equipmentModel='ae137288-3782-432d-8d83-d5cee733fe4b', context=SmartBoard_Context)
    #     print(i)
    #manager.equipment.remove('bce83c7b-cf46-4495-9bad-e057b8a39aeb')
    #equipment.remove('326e7adf-＃41ef-44c8-9071-6＃50af3554c0c')
    import time
    startT = time.time()
    print(manager.service.enable('85c72518-c304-463f-b925-d2cb1cf54791', 'user1'))
    endT = time.time()
    print(endT-startT)
    #print(manager.event.report_threat('f25d6fab-a140-42eb-b31b-3b9d94e96b19', 'Unexpected_Occupancy'))
    #print(manager.event.remove_threat('85098e99-ea6e-4be3-9476-eb0d6d6ef040'))
    #print(manager.service.disable('85c72518-c304-463f-b925-d2cb1cf54791'))

