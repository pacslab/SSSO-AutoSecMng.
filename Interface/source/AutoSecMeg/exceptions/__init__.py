class URIAlreadyExists(Exception):
    def __init__(self, URI='', type=''):
        self.URI = URI
        print("URI '{}' '{}' already exists".format(URI, 'type '+type))

class URIDoesNotExist(Exception):
    def __init__(self, URI='', type=''):
        self.message = "URI does not exist"
        self.URI = URI
        print("URI '{}' '{}' does not exist".format(URI, 'type '+type))

class EndpointInaccessible(Exception):
    def __init__(self, URI='', addr=''):
        self.message = "Endpoint is inaccessible"
        self.URI = URI
        print("Cannot access endpoint URI {} Address {}".format(URI, addr))