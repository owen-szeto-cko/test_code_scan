import requests
import csv
import base64
import requests
import ssl
import os
import jwt
import sys
import warnings

from datetime import date, datetime
from time import mktime
from wsgiref.handlers import format_date_time
from six import integer_types, iteritems, text_type
from OpenSSL import crypto

MERCHANT_ID = 'foodpanda_th_main'
HOST = "https://api.cybersource.com" 
PRIMITIVE_TYPES = (float, bool, bytes, text_type) + integer_types
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Based on a token list provided by FoodPanda, Invoke CyberSource API to retrieve PAN for each token from the token list, 
# and stored the result in a csv file with Checkout.com Token Migration file format
# 
# This function will read the CyberSource Card API and obtain the full pan inside the memory. 
# This function will then write the Full Card PAN into csv file. 
# This call could be updated such that the file is encrypted, or importing into our Vault directly without storing as pain text file.
def main():
    if len(sys.argv) != 3: 
        print("Usage: python3 FoodPanda_Token_export.py [input_filename] [output_filename]")
        return -1
    
    input_filename, output_filename = sys.argv[1], sys.argv[2] 
    input_filename = "in/" + input_filename
    output_filename = "out/" + output_filename
    os.makedirs(os.path.dirname(output_filename), exist_ok=True)

    fieldNames = [
        '~card_id~',
        '~customer_email~',
        '~customer_name~',
        '~cc_number~',
        '~cc_exp_month~',
        '~cc_exp_year~',
        '~AddressLine1~',
        '~AddressLine2~',
        '~AddressPostal~',
        '~AddressCity~',
        '~AddressState~',
        '~AddressCountry~',
        '~AddressPhone~'
        '~Status~'
    ]

    with open(input_filename, 'r') as input_file: # TODO confirm DH token_list file format (csv?)
        with open(output_filename, 'w', newline='\r\n') as output_csv: # for windows format line feed
            token_list = csv.DictReader(input_file)
            writer = csv.writer(output_csv, delimiter="|")
            writer.writerow(fieldNames)

            for row in token_list:
                token = row['column2'] # TODO confirm col name 
                res = getPaymentInstrument(token)

                try:
                    if res == None: raise ValueError()
                    else:           res = res.json()
                
                    # Make sure all necessary exists and not empty
                    if 'billTo' not in res or \
                    'email' not in res['billTo'] or \
                    '_embedded' not in res or \
                    'instrumentIdentifier' not in res['_embedded'] or \
                    'card' not in res['_embedded']['instrumentIdentifier'] or \
                    'number' not in res['_embedded']['instrumentIdentifier']['card'] or \
                    'card' not in res or \
                    'expirationMonth' not in res['card'] or \
                    'expirationYear' not in res['card'] or \
                        'id' not in res or \
                        res['billTo']['email'] == None or \
                        res['_embedded']['instrumentIdentifier']['card']['number'] == None or \
                        res['card']['expirationMonth'] == None or \
                        res['card']['expirationYear'] == None or \
                        res['id'] == None:
                            raise KeyError()

                    customer_name = ''
                    if 'firstName' in res['billTo']:
                        customer_name += res['billTo']['firstName']
                    if 'lastName' in res['billTo']:
                        if customer_name != '': customer_name += " "
                        customer_name += res['billTo']['lastName']
                    
                    writer.writerow([
                        "~"+res['id']+"~",
                        "~"+res['billTo']['email']+"~",
                        "~"+customer_name+"~",
                        "~"+res['_embedded']['instrumentIdentifier']['card']['number']+"~",
                        "~"+res['card']['expirationMonth']+"~",
                        "~"+res['card']['expirationYear']+"~",
                        "~"+res['billTo']['address1']+"~"           if 'address1'           in res['billTo'] else "~~",
                        "~"+res['billTo']['address2']+"~"           if 'address2'           in res['billTo'] else "~~",
                        "~"+res['billTo']['postalCode']+"~"         if 'postalCode'         in res['billTo'] else "~~",
                        "~"+res['billTo']['locality']+"~"           if 'locality'           in res['billTo'] else "~~",
                        "~"+res['billTo']['administrativeArea']+"~" if 'administrativeArea' in res['billTo'] else "~~",
                        "~"+res['billTo']['country']+"~"            if 'country'            in res['billTo'] else "~~",
                        "~"+res['billTo']['phoneNumber']+"~"        if 'phoneNumber'        in res['billTo'] else "~~",
                        "~OK~"
                    ])
                except:
                    writer.writerow([
                        "~"+token+"~",
                        "~~", "~~", "~~", "~~", "~~", "~~", "~~", "~~", "~~", "~~", "~~", "~~", 
                        "~Error~"
                    ])
                    continue


# Invoke CyberSource API to retrieve Card PAN via a token 
# @in_para: token
# @return: json_response with Full Card Pan. Full card PAN will be stored in memory.
def getPaymentInstrument(token):
    resource = '/tms/v1/paymentinstruments/' + token
    method = 'get'
    time = getDateTime()
    
    header_params = {}
    header_params['Accept-Encoding'] = '*'
    header_params['Content-Type'] = 'application/json'

    token = "Bearer " + get_token(method, time)
    header_params['Authorization'] = str(token)
    header_params = sanitize_for_serialization(header_params)
    header_params = dict(parameters_to_tuples(header_params, None))

    url = HOST + resource
    res = requests.get(url=url, headers=header_params)
    
    requests.Session

    return res if res.status_code == 200 else None


# Fetch the .p12 certificate and private key that provided by FoodPanda, 
# and used for Authorization for each CyberSource API call
#
# No parameter. 
# Return: CyberSource API certificate.  
def fetch_certificate_info():
    filecache = {}
    filename = 'delivery_hero'
    
    p12 = crypto.load_pkcs12(
        open(os.path.join(os.getcwd(), filename) + ".p12", 'rb').read(), # indicate .p12 file location (should be delivery_hero.p12 and the same directory as this script)
        'delivery_hero')                                                 # password

    cert_str = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate())
    der_cert_string = base64.b64encode(ssl.PEM_cert_to_DER_cert(cert_str.decode("utf-8")))
    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey()).decode("utf-8")

    filecache.setdefault(str(filename), []).append(der_cert_string)
    filecache.setdefault(str(filename), []).append(private_key)

    return filecache[filename]


# CyberSource helper for creating Authorization header
# https://github.com/CyberSource/cybersource-rest-samples-python/blob/master/samples/authentication/sample_code/StandAloneJWT.py
#
# Validation methods 
def parameters_to_tuples(params, collection_formats):
    new_params = []
    if collection_formats is None:
        collection_formats = {}
    for k, v in iteritems(params) if isinstance(params, dict) else params:
        if k in collection_formats:
            collection_format = collection_formats[k]
            if collection_format == 'multi':
                new_params.extend((k, value) for value in v)
            else:
                if collection_format == 'ssv':
                    delimiter = ' '
                elif collection_format == 'tsv':
                    delimiter = '\t'
                elif collection_format == 'pipes':
                    delimiter = '|'
                else:  # csv is the default
                    delimiter = ','
                new_params.append(
                    (k, delimiter.join(str(value) for value in v)))
        else:
            new_params.append((k, v))
    return new_params

# Data structure serialization. 
def sanitize_for_serialization(obj):
        if obj is None:
            return None
        elif isinstance(obj, PRIMITIVE_TYPES):
            return obj
        elif isinstance(obj, list):
            return [sanitize_for_serialization(sub_obj)
                    for sub_obj in obj]
        elif isinstance(obj, tuple):
            return tuple(sanitize_for_serialization(sub_obj)
                         for sub_obj in obj)
        elif isinstance(obj, (datetime, date)):
            return obj.isoformat()

        if isinstance(obj, dict):
            obj_dict = obj
        else:
            obj_dict = {obj.attribute_map[attr]: getattr(obj, attr)
                        for attr, _ in iteritems(obj.swagger_types)
                        if getattr(obj, attr) is not None}

        return {key: sanitize_for_serialization(val)
                for key, val in iteritems(obj_dict)}

def get_token(method, time):
    jwt_body = { "iat": time }

    # Reading the .p12 file
    cache_memory = fetch_certificate_info()
    der_cert_string = cache_memory[0]
    private_key = cache_memory[1]

    # Setting the headers - merchant_id and the public key
    headers_jwt = { "v-c-merchant-id": str(MERCHANT_ID) }

    public_key_list = ([])
    public_key_list.append(der_cert_string.decode("utf-8"))
    public_key_headers = { "x5c": public_key_list }

    headers_jwt.update(public_key_headers)

    # generating the token of jwt
    encoded_jwt = jwt.encode(jwt_body, private_key, algorithm='RS256', headers=headers_jwt)
    return encoded_jwt.encode("utf-8").decode("utf-8")

# Get current Datetime for authorization
def getDateTime():
    now = datetime.now()
    stamp = mktime(now.timetuple())
    return format_date_time(stamp)

if __name__ == "__main__":
    main()
