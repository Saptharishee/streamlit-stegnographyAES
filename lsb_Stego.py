import streamlit as st
import os
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
import cv2
from Crypto.Random import get_random_bytes


def convert_to_decimal(test_str):
    res = ''.join(format(ord(i), '08b') for i in test_str)
    return res


def decode_binary_string(s):
    return ''.join(chr(int(s[i*8:i*8+8],2)) for i in range(len(s)//8))

def decimalToBinary(n):
    return bin(n).replace("0b", "")
  
#Image size is 256*256
#Considering two pixels to be changed,
#Maximum change is 2*3*256*256
#However we will cap it at 9999 characters
#9999 characters requires 8*4 = 32 bits
#First 12 bits will be required to specify the length

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
username=st.text_input("Username", key="username" )
password=st.text_input("Password",key="password")
# enkey=st.text_input("Encryption key", 'sixteencharecter',key="enkey")
url=st.text_input(" Website ",key="url") 
img = st.file_uploader("Choose a file",key='img',type=['png','jpeg','jpg'])
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

if st.button('Submit'):
    enc_img=LSB_Steg()
    txt=bytes(decrypt(enc_img),'utf-8')
    st.write("Decryption of cipher ")
    cipher = AES.new(enkey, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("The message is authentic:", plaintext)
    except ValueError:
        print("Key incorrect or message corrupted")
    st.write(plaintext)

