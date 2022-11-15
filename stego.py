import streamlit as st
import os
from PIL import Image
import numpy as np
from Crypto.Cipher import AES

from Crypto.Random import get_random_bytes
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from googleapiclient.http import MediaFileUpload

import pickle
import os
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from google.auth.transport.requests import Request
import datetime



def Create_Service(client_secret_file, api_name, api_version, *scopes):
    print(client_secret_file, api_name, api_version, scopes, sep='-')
    CLIENT_SECRET_FILE = client_secret_file
    API_SERVICE_NAME = api_name
    API_VERSION = api_version
    SCOPES = [scope for scope in scopes[0]]
    print(SCOPES)

    cred = None

    pickle_file = f'token_{API_SERVICE_NAME}_{API_VERSION}.pickle'
    # print(pickle_file)

    if os.path.exists(pickle_file):
        with open(pickle_file, 'rb') as token:
            cred = pickle.load(token)

    if not cred or not cred.valid:
        if cred and cred.expired and cred.refresh_token:
            cred.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
            cred = flow.run_local_server()

        with open(pickle_file, 'wb') as token:
            pickle.dump(cred, token)

    try:
        # st.write("Vanakam da mapla inside create srvice")
        service = build(API_SERVICE_NAME, API_VERSION, credentials=cred)
        print(API_SERVICE_NAME, 'service created successfully')
        return service
    except Exception as e:
        print('Unable to connect.')
        print(e)
        return None

def convert_to_RFC_datetime(year=1900, month=1, day=1, hour=0, minute=0):
    dt = datetime.datetime(year, month, day, hour, minute, 0).isoformat() + 'Z'
    return dt
    
  

def convert_to_decimal(test_str):
    res = ''.join(format(ord(i), '08b') for i in test_str)
    return res


def decode_binary_string(s):
    return ''.join(chr(int(s[i*8:i*8+8],2)) for i in range(len(s)//8))

def decimalToBinary(n):
    return bin(n).replace("0b", "")


def LSB_Steg():
    string = str(ciphertext)
    message = convert_to_decimal(string)
    message_length = str(len(message))
    st.write("Original Message: ", string)
    
    if(len(message_length) > 4):
        st.write("String Length exceeded maximum value")
        return
    
    message_length = (4 - len(message_length))*"0" + message_length
    message = convert_to_decimal(str(message_length)) + message
    #Update Message Length
    message_length = len(message)
    st.write("The message : "+message)

    image = Image.open(img)
    image= np.array(image)
    
    org_img = image
    count = 0

    for i in range(0, len(image)):
        if(count >= int(message_length)):
            break
        for j in range(0, len(image[0])):
            if(count >= int(message_length)):
                break
            for k in range(0, len(image[0][0])):
                bgr = image[i][j][k]
                image[i][j][k] = int((str(decimalToBinary(bgr))[:-2] + message[count:count+2]), 2)
                count = count + 2
                if(count >= int(message_length)):
                    break      
    st.image( org_img,caption="Original Image")                
    st.image(image,caption="Image with encoded message")
    return image
    # cv2.moveWindow("Image with encoded message", 500, 180)
    
def decrypt(image):
    st.write("--------Message Encoded-------")
    count = 0
    encoded_msg_len = ""
    encoded_msg = ""
    
    #Reverse
    
    #First, we need to get the length of the message
    #Hence we decode the first 32 bits first.
    
    for i in range(0, len(image)):
        if(count == 32):
            break
        for j in range(0, len(image[0])):
            if(count == 32):
                break
            for k in range(0, len(image[0][0])):
                bgr = image[i][j][k]
                encoded_msg_len = encoded_msg_len + str(decimalToBinary(bgr))[-2:]
                count = count + 2
                if(count == 32):
                    break
    encoded_msg_len = int(decode_binary_string(encoded_msg_len))
    encoded_msg_len = encoded_msg_len + 32
    
    count = 0
    
    for i in range(0, len(image)):
        if(count >= int(encoded_msg_len)):
            break
        for j in range(0, len(image[0])):
            if(count >= int(encoded_msg_len)):
                break
            for k in range(0, len(image[0][0])):
                bgr = image[i][j][k]
                encoded_msg = encoded_msg + str(decimalToBinary(bgr))[-2:]
                count = count + 2
                if(count >= int(encoded_msg_len)):
                    break
    encrypted_msg= decode_binary_string(encoded_msg)[4:]
    st.write("Decoded Message: ", encrypted_msg)
    return encrypted_msg

def uplod_drive(image):

    file_metadata = {
    'name': img.name,
    'parents': ['1Vj6ANgwMJSxiciIrGm7bGZrUMh3H_f8B']
    }
    st.write(img.name)
    media_content = MediaFileUpload(PATH, mimetype='image/png')

    file = service.files().create(body=file_metadata,
                                media_body=media_content,
                                fields='id').execute()
    st.write(file)
   
username=st.text_input("Username", key="username" )
password=st.text_input("Password",key="password")

# enkey=st.text_input("Encryption key", 'sixteencharecter',key="enkey")
url=st.text_input(" Website ",key="url") 
img = st.file_uploader("Choose a file",key='img',type=['png','jpeg','jpg'])
img_name=img.name
PATH=os.path.join(os.path.dirname(__file__),'assets\\'+str(img_name))
#Encrypt through AES 
# enkey=bytes(enkey,'utf-8')
enkey = get_random_bytes(16)

# create new instance of cipher
cipher = AES.new(enkey, AES.MODE_EAX)

# data to be encrypted
data = username+"*"+"*"+password+"*"+"*"+url
data=data.encode("utf-8")
st.write(data)

# nonce is a random value generated each time we instantiate the cipher using new()
nonce = cipher.nonce

ciphertext, tag = cipher.encrypt_and_digest(data)
st.write(type(tag))

# encrypt the data


# print the encrypted data
st.write("Cipher text:", ciphertext)
def intialize ():
    CLIENT_SERVER_FILE = "client_secret_991368393238-qsq96s0h13ss2mghidedueu4do80pvaj.apps.googleusercontent.com.json"
    API_NAME='drive'
    API_VERSION='v3'
    SCOPES = ['https://www.googleapis.com/auth/drive']
    service = Create_Service(CLIENT_SERVER_FILE,API_NAME,API_VERSION,SCOPES)
    return service




gauth = GoogleAuth() 
drive = GoogleDrive(gauth)    

if st.button('Encrypt Upload and Decrypt  '):
    enc_img=LSB_Steg()
    
    service=intialize ()
    uplod_drive(enc_img)
    st.write("File uploded to drive")
# if st.button('Decrypt'):
    txt=bytes(decrypt(enc_img),'utf-8')
    st.write("Decryption of cipher ")
    cipher = AES.new(enkey, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        st.write("The message is authentic:", plaintext)
    except ValueError:
        print("Key incorrect or message corrupted")

    

    
    
